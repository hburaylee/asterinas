# SPDX-License-Identifier: MPL-2.0

{ stdenvNoCC, bashInteractive, busybox, sqlite, writeClosure, }:
let programs = [ bashInteractive busybox sqlite ];
in stdenvNoCC.mkDerivation {
  name = "kernelet-bash-bundle";
  buildCommand = ''
    mkdir -p $out/rootfs/{bin,dev,etc,nix/store,proc,root,run,sys,tmp,usr/bin}

    # Keep the programs' ELF loaders and libraries at their original store
    # paths inside the OCI rootfs.
    while IFS= read -r dependency; do
      cp -r "$dependency" $out/rootfs/nix/store/
    done < ${writeClosure programs}

    cp -r ${busybox}/bin/* $out/rootfs/bin/
    ln -s ${bashInteractive}/bin/bash $out/rootfs/bin/bash
    ln -sfn bash $out/rootfs/bin/sh
    ln -s ${sqlite}/bin/sqlite3 $out/rootfs/usr/bin/sqlite3
    chmod 1777 $out/rootfs/tmp

    cat > $out/config.json <<'EOF'
    {
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs", "readonly": false },
      "process": {
        "terminal": true,
        "user": { "uid": 0, "gid": 0 },
        "args": ["/bin/bash", "--noprofile", "--norc", "-i"],
        "env": ["PATH=/bin:/usr/bin", "HOME=/root", "TERM=xterm-256color", "PS1=kernelet# "],
        "cwd": "/"
      },
      "mounts": [
        { "destination": "/proc", "type": "proc", "source": "proc" },
        { "destination": "/sys", "type": "sysfs", "source": "sysfs" }
      ],
      "hostname": "kernelet"
    }
    EOF
  '';
}
