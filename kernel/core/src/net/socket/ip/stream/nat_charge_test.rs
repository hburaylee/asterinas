// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    device::{
        AnyNetworkDevice, Checksum, DeviceCapabilities, EthernetAddress, Medium, NetError,
        WithDevice,
    },
    ext::Ext,
    iface::{
        BindPortConfig, Iface, InterfaceFlags, InterfaceName, InterfaceType, IpIface,
        ScheduleNextPoll,
    },
    packet::{FreshTxPacket, LinkLayer, RxPacket, TxPacket},
    socket::{RawTcpOption, TcpListener},
    wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr},
};
use ostd::{
    mm::{VmReader, VmWriter},
    prelude::*,
};

use super::observer::StreamObserver;
use crate::{
    endovisor::NativeTcpBufferCharge,
    prelude::*,
    process::{credentials::Uid, signal::Pollee},
};

const LOCAL: [u8; 4] = [192, 0, 2, 1];
const REMOTE: [u8; 4] = [192, 0, 2, 2];
const LISTEN_PORT: u16 = 18080;
const RESERVED_BYTES: usize = 2 * 1024 * 1024;

// Exercise the native protocol owners with the production StreamObserver.
// Only the device boundary is controlled: no socket or quota logic is replaced.
#[ktest]
fn listener_backlog_retains_charge_until_last_reset_is_sent() {
    aster_time::init_for_ktest();
    let owner = Uid::new(u32::MAX - 61);
    assert_eq!(NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner), 0);
    let charge = Arc::new(NativeTcpBufferCharge::reserve_for_ktest(owner, RESERVED_BYTES).unwrap());
    let weak = Arc::downgrade(&charge);
    let observer = StreamObserver::new(Pollee::new(), Some(charge.clone()));
    let mut fixture = Fixture::new(observer);

    // One established connection and one incomplete handshake exercise both
    // backlog collections. Neither connection is accepted into a socket file.
    let server_seq = fixture.syn(40000);
    fixture.inject(tcp_packet(40000, 42, server_seq.wrapping_add(1), 0x10));
    fixture.iface.poll();
    assert!(fixture.listener.as_ref().unwrap().can_accept());
    fixture.syn(40001);

    fixture.device.lock().tx_budget = Some(0);
    fixture.close_listener();
    drop(charge);
    for _ in 0..3 {
        fixture.iface.poll();
    }
    assert!(weak.upgrade().is_some());
    assert_eq!(
        NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner),
        RESERVED_BYTES
    );
    assert_eq!(fixture.reset_count(), 0);

    // Releasing only one backlog owner must not refund the shared reservation.
    fixture.device.lock().tx_budget = Some(1);
    fixture.iface.poll();
    assert_eq!(fixture.reset_count(), 1);
    assert!(weak.upgrade().is_some());
    assert_eq!(
        NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner),
        RESERVED_BYTES
    );

    fixture.device.lock().tx_budget = None;
    fixture.iface.poll();
    assert_eq!(fixture.reset_count(), 2);
    assert!(weak.upgrade().is_none());
    assert_eq!(NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner), 0);

    // The same UID can reserve the refunded amount again. Additional polls
    // cannot release it a second time or damage this replacement reservation.
    let replacement = NativeTcpBufferCharge::reserve_for_ktest(owner, RESERVED_BYTES).unwrap();
    fixture.iface.poll();
    assert_eq!(
        NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner),
        RESERVED_BYTES
    );
    drop(replacement);
    assert_eq!(NativeTcpBufferCharge::endpoint_bytes_for_ktest(owner), 0);
}

struct TestExt;

impl Ext for TestExt {
    type ScheduleNextPoll = NoSchedule;
    type TcpEventObserver = StreamObserver;
    type UdpEventObserver = ();
}

struct NoSchedule;

impl ScheduleNextPoll for NoSchedule {
    fn schedule_next_poll(&self, _: Option<u64>) {}
}

struct Fixture {
    device: Arc<Mutex<TestDevice>>,
    iface: Arc<dyn Iface<TestExt>>,
    listener: Option<TcpListener<TestExt>>,
}

impl Fixture {
    fn new(observer: StreamObserver) -> Self {
        let device = Arc::new(Mutex::new(TestDevice {
            incoming: VecDeque::new(),
            outgoing: Vec::new(),
            tx_budget: None,
        }));
        let iface: Arc<dyn Iface<TestExt>> = IpIface::new(
            Driver(device.clone()),
            Ipv4Cidr::new(Ipv4Address::from(LOCAL), 24),
            None,
            InterfaceName::from_str_truncated("nat-charge-test"),
            NoSchedule,
            InterfaceType::LOOPBACK,
            InterfaceFlags::UP | InterfaceFlags::RUNNING,
        );
        let bound = iface
            .bind_tcp(BindPortConfig::new(
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(LOCAL)), LISTEN_PORT),
                false,
            ))
            .unwrap();
        let listener = TcpListener::new_listen(
            bound,
            8,
            &RawTcpOption {
                keep_alive: None,
                is_nagle_enabled: false,
            },
            observer,
        )
        .unwrap_or_else(|_| panic!("test listener must bind successfully"));
        Self {
            device,
            iface,
            listener: Some(listener),
        }
    }

    fn inject(&self, packet: Vec<u8>) {
        self.device.lock().incoming.push_back(packet);
    }

    fn syn(&self, port: u16) -> u32 {
        self.inject(tcp_packet(port, 41, 0, 0x02));
        self.iface.poll();
        let device = self.device.lock();
        let reply = device
            .outgoing
            .iter()
            .rev()
            .find(|packet| packet.len() >= 40 && packet[33] & 0x12 == 0x12)
            .expect("real native TCP must reply with SYN/ACK");
        assert_eq!(u16::from_be_bytes(reply[22..24].try_into().unwrap()), port);
        u32::from_be_bytes(reply[24..28].try_into().unwrap())
    }

    fn reset_count(&self) -> usize {
        self.device
            .lock()
            .outgoing
            .iter()
            .filter(|packet| packet.len() >= 40 && packet[33] & 0x04 != 0)
            .count()
    }

    fn close_listener(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.close();
            drop(listener);
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // An unwinding assertion still removes native socket registrations.
        self.device.lock().tx_budget = None;
        self.close_listener();
        self.iface.poll();
    }
}

// All frames are IPv4/TCP without options. Checksums are explicitly disabled
// in this test device, as they are unrelated to native socket ownership.
fn tcp_packet(source_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&REMOTE);
    packet[16..20].copy_from_slice(&LOCAL);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&LISTEN_PORT.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&ack.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&65535u16.to_be_bytes());
    packet
}

struct Driver(Arc<Mutex<TestDevice>>);

impl WithDevice for Driver {
    type Device = TestDevice;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn AnyNetworkDevice) -> R,
    {
        let mut device = self.0.lock();
        f(&mut *device)
    }
}

#[derive(Debug)]
struct TestDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: Vec<Vec<u8>>,
    // None permits unlimited transmission; Some(0) models Host TX pressure.
    tx_budget: Option<usize>,
}

impl AnyNetworkDevice for TestDevice {
    fn mac_addr(&self) -> EthernetAddress {
        EthernetAddress::default()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities.checksum.ipv4 = Checksum::None;
        capabilities.checksum.tcp = Checksum::None;
        capabilities
    }

    fn can_receive(&self) -> bool {
        !self.incoming.is_empty()
    }

    fn can_send(&self) -> bool {
        self.tx_budget != Some(0)
    }

    fn receive(&mut self) -> core::result::Result<RxPacket<LinkLayer>, NetError> {
        let bytes = self.incoming.pop_front().ok_or(NetError::NotReady)?;
        let mut builder = FreshTxPacket::<LinkLayer>::alloc(bytes.len())
            .unwrap()
            .to_builder();
        let written = builder
            .append_writer()
            .write(&mut VmReader::from(bytes.as_slice()));
        assert_eq!(written, bytes.len());
        builder.commit(written);
        Ok(builder.build().to_rx_packet().unwrap())
    }

    fn send(&mut self, packet: TxPacket<LinkLayer>) -> core::result::Result<(), NetError> {
        if let Some(budget) = &mut self.tx_budget {
            if *budget == 0 {
                return Err(NetError::Busy);
            }
            *budget -= 1;
        }
        let mut bytes = vec![0; packet.len()];
        let read = packet
            .reader()
            .read(&mut VmWriter::from(bytes.as_mut_slice()));
        assert_eq!(read, bytes.len());
        self.outgoing.push(bytes);
        Ok(())
    }

    fn alloc_tx_buffer(payload_len: usize) -> ostd::Result<FreshTxPacket> {
        FreshTxPacket::alloc(payload_len)
    }

    fn free_processed_tx_buffers(&mut self) {}

    fn notify_poll_end(&mut self) {}
}
