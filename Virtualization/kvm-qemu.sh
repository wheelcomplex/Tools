#!/bin/bash

# Copyright (C) 2011-2019 DoomedRaven.
# This file is part of Tools - https://github.com/doomedraven/Tools
# See the file 'LICENSE.md' for copying permission.

: '
Huge thanks to:
    * @SamRSA8
    * @http_error_418
    * @2sec4you
    * @seifreed
    * @Fire9
    * @abuse_ch
'

#ToDo investigate
#https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
#when backing storage is attached to virtio_blk (vda, vdb, etc.) storage controller - performance from iSCSI client connecting to the iSCSI target was in my environment ~ 20 IOPS, with throughput (depending on IO size) ~ 2-3 MiB/s. I changed virtual disk controller within virtual machine to SCSI and I'm able to get 1000+ IOPS and throughput 100+ MiB/s from my iSCSI clients.

#https://linux.die.net/man/1/qemu-img
#"cluster_size"
#Changes the qcow2 cluster size (must be between 512 and 2M). Smaller cluster sizes can improve the image file size whereas larger cluster sizes generally provide better performance.


# https://www.doomedraven.com/2016/05/kvm.html
# Use Ubuntu 18.04 LTS

# https://github.com/dylanaraps/pure-bash-bible
# https://www.shellcheck.net/

# ACPI tables related
# https://wiki.archlinux.org/index.php/DSDT
# Dump on linux
#   acpidump > acpidump.out
# Dump on Windows
#    https://acpica.org/downloads/binary-tools
#    acpixtract -a acpi/4/acpi.dump

# acpixtract -a acpidump.out
# iasl -d DSDT.dat
# Decompile: iasl -d dsdt.dat
# Recompile: iasl -tc dsdt.dsl

#      strs[0] = "KVMKVMKVM\0\0\0"; /* KVM */
#      strs[1] = "Microsoft Hv"; /* Microsoft Hyper-V or Windows Virtual PC */
#      strs[2] = "VMwareVMware"; /* VMware */
#      strs[3] = "XenVMMXenVMM"; /* Xen */
#      strs[4] = "prl hyperv  "; /* Parallels */
#      strs[5] = "VBoxVBoxVBox"; /* VirtualBox */

#https://www.qemu.org/download/#source or https://download.qemu.org/
qemu_version=4.0.0
# libvirt - https://libvirt.org/sources/
# changelog - https://libvirt.org/news.html
libvirt_version=5.3.0
# https://virt-manager.org/download/
virt_viewer_version=8.0
# virt-manager - https://github.com/virt-manager/virt-manager/releases
virt_manager_version=2.1.0
# http://download.libguestfs.org/
libguestfs_version=1.40.2
# autofilled
OS=""
username=""

# ToDO add to see if cpu supports VTx
# egrep '(vmx|svm)' --color=always /proc/cpuinfo
#* If your CPU is Intel, you need activate in __BIOS__ VT-x
#    * (last letter can change, you can activate [TxT ](https://software.intel.com/en-us/blogs/2012/09/25/how-to-enable-an-intel-trusted-execution-technology-capable-server) too, and any other feature, but VT-* is very important)

set -x
set -e

function changelog() {
cat << EndOfCL
    # 07.06.2019 - add virt-viewer installation
    # 24.04.2019 - QEMU 4
    # 28.03.2019 - Huge cleanup, fixes, QEMU 4-RC2 testing in dev
    # 24.02.2019 - Add Mosh + support for Linux TCP BBR - https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
    # 11.02.2019 - Depricated linked clones and added WebVirtMgr
    # 30.01.2019 - Libvirt 5.0.0
    # 27.12.2018 - libguestfs 1.38
    # 10.11.2018 - Virt-manager 2, libivrt-4.10, fixes
    # 11.09.2018 - code improvement
    # 09.09.2018 - ACPI fixes
    # 05.09.2018 - libivrt 4.7 and virtlogd
    # 19.08.2018 - Intel HAXM notes
    # 14.08.2018 - QEMU 3 support tested on ubuntu 18.04
    # 03.08.2018 - More anti-anti
    # 28.02.2018 - Support for qemu 2.12
EndOfCL
}

function usage() {
cat << EndOfHelp
    Usage: $0 <func_name> <args>
    Commands - are case insensitive:
        all [username_optional] - Execs QEMU/SeaBios/KVM, username is optional
        qemu - Install QEMU from source,
            DEFAULT support are x86 and x64, set ENV var QEMU_TARGERS=all to install for all arches
        SeaBios - Install SeaBios and repalce QEMU bios file
        KVM - this will install intel-HAXM if you on Mac
        HAXM - Mac Hardware Accelerated Execution Manager
        grub - add IOMMU to grub command line
        tcp_bbr - Enable TCP BBR congestion control
            * https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
        Mosh - mobile shell - https://mosh.org/
        WebVirtMgr - Install WebManager for KVM
        Clone - <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_range_base>
                * Example Win7x64 /VMs/Win7x64.qcow2 0 5 /var/lib/libvirt/images/ 192.168.1
                https://wiki.qemu.org/Documentation/CreateSnapshot
        libvirt [username_optional] - install libvirt, username is optional
        Libvmi - install LibVMI
        Virtmanager - install virt-manager
        virtviewer - install virt-viewer
        Libguestfs - install libguestfs
        Replace_qemu - only fix antivms in QEMU source
        Replace_seabios <path> - only fix antivms in SeaBios source
        Issues - will give you error - solution list
        noip - Install No-ip deamon and enable on boot

    Tips:
        * Latest kernels having some KVM features :)
            * apt search linux-image
        * QCOW2 allocations types performance
            * https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
            * https://www.jamescoyle.net/how-to/2060-qcow2-physical-size-with-different-preallocation-settings
EndOfHelp
}

function grub_iommu(){
    # ToDo make a sed with regex which works on all cases
    echo "[+] Updating GRUB for IOMMU support"
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="intel_iommu=on"/g' /etc/default/grub || true
    if [ -z "$(cat /etc/default/grub | grep 'intel_iommu=on')" ]
    then
        echo "[-] GRUB patching failed, add intel_iommu=on manually"
        return 0
    fi
    update-grub
    echo "[+] grub config updated, please reboot"
}

function _sed_aux(){
    # pattern path error_msg
    echo $1 $2 $3
    if [ -f "$2" ] && ! sed -i "$1" $2; then
        echo $3
    fi
}

function _enable_tcp_bbr() {
    # https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
    # grep 'CONFIG_TCP_CONG_BBR' /boot/config-$(uname -r)
    # grep 'CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    # egrep 'CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    echo "net.core.default_qdisc=fq" >> /etc/security/limits.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/security/limits.conf

    sysctl --system
}

function _check_brew() {
    if [ ! -f /usr/local/bin/brew ]; then
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
}

function install_haxm_mac() {
    _check_brew
    brew cask install intel-haxm
    brew tap jeffreywildman/homebrew-virt-manager
    brew cask install xquartz
    brew install virt-manager virt-viewer

    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
}

function install_libguestfs() {

    echo "[+] Check for previous version of LibGuestFS"
    apt purge -y "libguestfs-*"  

    apt install gperf flex bison libaugeas-dev libhivex-dev supermin ocaml-nox libhivex-ocaml genisoimage libhivex-ocaml-dev libmagic-dev libjansson-dev -y 2>/dev/null
    cd ${BUILDTMPDIR} || return
    test ! -s "libguestfs-$libguestfs_version.tar.gz" && wget "http://download.libguestfs.org/1.40-stable/libguestfs-$libguestfs_version.tar.gz"
    tar xf "libguestfs-$libguestfs_version.tar.gz"
    cd libguestfs-$libguestfs_version || return
    ./configure
    make -j$(nproc)
    REALLY_INSTALL=yes checkinstall -D --pkgname=libvirt-$libguestfs_version --default
    # ln -s /usr/local/lib/libguestfs.so.0 /lib/x86_64-linux-gnu/libguestfs.so.0
}

function install_libvmi() {
    # IMPORTANT:
    # 1)
    # LibVMI will have KVM support if libvirt is available during compile time.
    #
    # 2)
    # Enable GDB access to your KVM VM. This is done by adding '-s' to the VM creation line or, by modifying the VM XML definition used by libvirt as follows:
    # Change:
    # <domain type='kvm'>
    # to:
    # <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    #
    # Add:
    # <qemu:commandline>
    #   <qemu:arg value='-s'/>
    # </qemu:commandline>
    # under the <domain> level of the XML.

    # The -s switch is a shorthand for -gdb tcp::1234

    # LibVMI
    cd ${BUILDTMPDIR} || return

    if [ ! -d "libvmi" ]; then
        git clone https://github.com/libvmi/libvmi.git
        echo "[+] Cloned LibVMI repo"
    fi
    cd "libvmi" || return

        # install deps
        apt-get install -y cmake flex bison libglib2.0-dev libjson-c-dev libyajl-dev
        # other deps
        apt-get install -y pkg-config
        mkdir build
        cd build || return
        cmake -DENABLE_XEN=ON -DENABLE_KVM=ON -DENABLE_XENSTORE=OFF -DENABLE_BAREFLANK=OFF ..
        make -j$(nproc)
        make install
        /sbin/ldconfig

        # LibVMI Python
        cd ${BUILDTMPDIR} || return

    if [ ! -d "python_Libvmi" ]; then
        # actual
        # https://github.com/libvmi/python/tree/76d9ea85eefa0d77f6ad4d6089e757e844763917
        # git checkout add_vmi_request_page_fault
        # git pull
        git clone https://github.com/libvmi/python.git python_Libvmi
        echo "[+] Cloned LibVMI Python repo"
    fi
    cd "python_Libvmi" || return

        # install deps
    apt-get install -y python3-pkgconfig python3-cffi python3-future
        python setup.py build
        python setup.py install
        # python3
        python3 setup.py build
        python3 setup.py install

        # Rekall
        cd ${BUILDTMPDIR} || return

    if [ ! -d "rekall" ]; then
        git clone https://github.com/google/rekall.git
        echo "[+] Cloned Rekall repo"
    fi

        virtualenv ${BUILDTMPDIR}/MyEnv
        source ${BUILDTMPDIR}/MyEnv/bin/activate

        if [ -z "$(which pip3)" ]
        then
        echo "command pip3 not found, try to install it first (apt install python3-pip)"
        apt install python-pip3 -y || exit $?
        fi

        pip3 install --upgrade testresources setuptools pip wheel
        pip3 install capstone
        pip3 install --editable rekall/rekall-lib
        # ERROR: rekall-efilter 1.6.0 has requirement future==0.16.0
        pip3 install future==0.16.0
        # TypeError: Set() missing 1 required positional argument: 'value'
        pip3 install pyaff4==0.26.post6
        pip3 install --editable rekall/rekall-core
        pip3 install --editable rekall/rekall-agent
        pip3 install --editable rekall
        pip3 install --upgrade pyasn1
        deactivate
}

# In progress...
# Errors: "The selected hypervisor has no events support!" - only Xen supported unfortunately
# 
function install_pyvmidbg() {
        # deps
        apt-get install python3-docopt python3-lxml cabextract

        # libvmi config entry
        #
    # /etc/libvmi.conf:
        # win10 {
        #    ostype = "Windows";
        #    rekall_profile = "/etc/libvmi/rekall-profile.json";
        # }

        # Make Windows 10 profile
        # Copy from Guest OS file "C:\Windows\System32\ntoskrnl.exe"
        # rekall peinfo -f <path/to/ntoskrnl.exe>
        #
        # Once the PDB filename and GUID is known, creating the Rekall profile is done in two steps:
        # rekall fetch_pdb <PDB filename> <GUID>
        # rekall parse_pdb <PDB filename> > rekall-profile.json
        #
        # In case of Windows 10:
        # rekall fetch_pdb ntkrnlmp <GUID>
        # May cause error like "ERROR:rekall.1:Unrecognized type T_64PUINT4" (not dangerous)
        # rekall parse_pdb ntkrnlmp > rekall-profile.json

        # install rekall profile
        # /etc/libvmi/rekall-profile.json

        # git clone https://github.com/Wenzel/pyvmidbg.git
        # virtualenv -p python3 venv
        # source venv/bin/activate
        # pip install .

        # python3 -m vmidbg 5000 <vm_name> --address 0.0.0.0 cmd -d

        # git clone https://github.com/radare/radare2.git
        # sys/install.sh
        # r2 -d gdb://127.0.0.1:5000 -b 64

}

function install_libvirt() {
    # http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    #rm -r /usr/local/lib/python2.7/dist-packages/libvirt*

	rm -f "${BUILDTMPDIR}/task.libvirt.done"

        # doomedraven changed to libvirtinstall - so later not to forget what it is intended for
    if [ ! -f /etc/apt/preferences.d/libvirtinstall ]; then
    # set to hold to avoid side problems
        cat >> /etc/apt/preferences.d/libvirtinstall << EOH
Package: libvirt-bin
Pin: release *
Pin-Priority: -1
Package: libvirt0
Pin: release *
Pin-Priority: -1
EOH
    fi

    echo "[+] Checking/deleting old versions of Libvirt"
    apt-get purge libvirt0 libvirt-bin -y >/dev/null
        oldpkgs=$(dpkg -l|grep "libvirt-[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3)
        test -n "$oldpkgs" && echo "$oldpkgs" | xargs apt purge -y 2>/dev/null

    cd ${BUILDTMPDIR} || return
    if [ ! -f  libvirt-$libvirt_version.tar.xz ]; then
        wget https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz
    fi
    tar xf libvirt-$libvirt_version.tar.xz
    cd libvirt-$libvirt_version || return
    if [ "$OS" = "Linux" ]; then
        apt-get install python-dev python3-dev unzip numad glib-2.0 libglib2.0-dev libsdl1.2-dev lvm2 python-pip python-libxml2 python3-libxml2 ebtables libosinfo-1.0-dev libnl-3-dev libnl-route-3-dev libyajl-dev xsltproc libapparmor-dev libdevmapper-dev libpciaccess-dev dnsmasq dmidecode librbd-dev -y >/dev/null
        #apt-get install apparmor-profiles apparmor-profiles-extra apparmor-utils libapparmor-dev python-apparmor libapparmor-perl -y
        pip install ipaddr >/dev/null
        # --prefix=/usr --localstatedir=/var --sysconfdir=/etc
        ./autogen.sh --system  --with-qemu=yes --with-dtrace --with-numad --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=yes --with-vz=no   --with-esx=no --with-hyperv=no --with-yajl=yes --with-secdriver-apparmor=yes --with-apparmor-profiles
        make -j$(nproc)
        checkinstall -D --pkgname=libvirt-$libvirt_version --default
        # check if linked correctly
        if [ -f /usr/lib/libvirt-qemu.so ]; then
            libvirt_so_path=/usr/lib/
            export PKG_CONFIG_PATH=/usr/lib/pkgconfig/
        elif [ -f /usr/lib64/libvirt-qemu.so ]; then
            libvirt_so_path=/usr/lib64/
            export PKG_CONFIG_PATH=/usr/lib64/pkgconfig/
        fi

        if [ ! -z "$libvirt_so_path" ]; then
            # #ln -s /usr/lib64/libvirt-qemu.so /lib/x86_64-linux-gnu/libvirt-qemu.so.0
            for so_path in $(ls ${libvirt_so_path}libvirt*.so); 
			do
				ln -sf $so_path /lib/$(uname -m)-linux-gnu/$(basename $so_path);
				ln -sf /lib/$(uname -m)-linux-gnu/$(basename $so_path) /lib/$(uname -m)-linux-gnu/$(basename $so_path).0
			done
        fi

    elif [ "$OS" = "Darwin" ]; then
        ./autogen.sh --system --prefix=/usr/local/ --localstatedir=/var --sysconfdir=/etc --with-qemu=yes --with-dtrace --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=no --with-vz=no   --with-esx=no --with-hyperv=no --with-wireshark-dissector=no --with-yajl=yes
    fi

    # https://wiki.archlinux.org/index.php/Libvirt#Using_polkit
    if [ -f /etc/libvirt/libvirtd.conf ]; then
        path="/etc/libvirt/libvirtd.conf"
    elif [ -f /usr/local/etc/libvirt/libvirtd.conf ]; then
        path="/usr/local/etc/libvirt/libvirtd.conf"
    fi

    sed -i 's/#unix_sock_group/unix_sock_group/g' "$path"
    sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' "$path"
    sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' "$path"
    sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' "$path"
    sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' "$path"

    #echo "[+] Setting AppArmor for libvirt/kvm/qemu"
    sed -i 's/#security_driver = "selinux"/security_driver = "apparmor"/g' /etc/libvirt/qemu.conf
    # https://gitlab.com/apparmor/apparmor/wikis/Libvirt
    FILES=(
        /etc/apparmor.d/usr.sbin.libvirtd
        /usr/sbin/libvirtd
    )
    for file in "${FILES[@]}"; do
        if [ -f $file ]; then
            aa-complain $file || true
        fi 
    done
    cd ${BUILDTMPDIR} || return

    if [ ! -f v$libvirt_version.zip ]; then
        wget https://github.com/libvirt/libvirt-python/archive/v$libvirt_version.zip
    fi
    if [ -d "libvirt-python-$libvirt_version" ]; then
        rm -r "libvirt-python-$libvirt_version"
    fi
    unzip v$libvirt_version.zip
    cd "libvirt-python-$libvirt_version" || return
    python3 setup.py build
    python3 setup.py install
    #py2
    python setup.py build
    python setup.py install
    if [ "$OS" = "Linux" ]; then
        # https://github.com/libvirt/libvirt/commit/e94979e901517af9fdde358d7b7c92cc055dd50c
        groupname=""
        if grep -q -E '^libvirtd:' /etc/group; then
            groupname="libvirtd"
        elif grep -q -E '^libvirt:' /etc/group; then
            groupname="libvirt"
        else
            # create group if missed
            groupname="libvirt"
            groupadd libvirt
        fi
        usermod -G $groupname -a "$(whoami)"
        if [ ! -z "$username" ]; then
            usermod -G $groupname -a "$username"
        fi
    fi

    systemctl enable libvirtd.service
    systemctl restart libvirtd.service
    systemctl enable virtlogd.socket
    systemctl restart virtlogd.socket

    echo "[+] Build libvirt done, you should logout and login "
	date > "${BUILDTMPDIR}/task.libvirt.done"
}

function virt_deps()
{
    # from build-dep
    apt install libgirepository1.0-dev gtk-doc-tools python-pip python3-pip gir1.2-govirt-1.0 libgovirt-dev \
    libgovirt-common libgovirt2 gir1.2-rest-0.7 unzip intltool augeas-doc ifupdown wodim cdrkit-doc indicator-application \
    augeas-tools radvd auditd systemtap nfs-common zfsutils pm-utils python-openssl-doc python-socks python-ntlm samba ovmf \
    debootstrap sharutils-doc ssh-askpass gnome-keyring python-requests python-six python-urllib3 python2.7 python2.7-minimal \
    sharutils spice-client-glib-usb-acl-helper ubuntu-mono x11-common python-cryptography python-dbus python-enum34 python-gi \
    python-gi-cairo python-idna python-ipaddr python-ipaddress  python-libxml2 python3-libxml2 python-minimal python-openssl python-pkg-resources \
    libxml2-utils libxrandr2 libxrender1 libxshmfence1 libxtst6 libxv1 libyajl2 msr-tools osinfo-db python python-asn1crypto \
    python-cairo python-certifi python-cffi-backend python-chardet libxcb-present0 libxcb-render0 libxcb-shm0 libxcb-sync1 \
    libxcb-xfixes0 libxcomposite1 libxcursor1 libxdamage1 libxen-4.9 libxenstore3.0 libxfixes3 libxft2 libxi6 libxinerama1 \
    libxkbcommon0 libusbredirhost1 libusbredirparser1 libv4l-0 libv4lconvert0 libvisual-0.4-0 libvorbis0a libvorbisenc2 libvpx5 \
    libvte-2.91-0 libvte-2.91-common libwavpack1 libwayland-client0 libwayland-cursor0 libwayland-egl1-mesa libwayland-server0 \
    libx11-xcb1 libxcb-dri2-0 libxcb-dri3-0 libsoup-gnome2.4-1 libsoup2.4-1 libspeex1 libspice-client-glib-2.0-8 \
    libspice-client-gtk-3.0-5 libspice-server1 libtag1v5 libtag1v5-vanilla libthai-data libthai0 libtheora0 libtiff5 \
    libtwolame0 libpython2.7 libpython2.7-minimal libpython2.7-stdlib librados2 libraw1394-11 librbd1 librdmacm1 librest-0.7-0 \
    librsvg2-2 librsvg2-common libsamplerate0 libsdl1.2debian libshout3 libsndfile1 libpango-1.0-0 libpangocairo-1.0-0 \
    libpangoft2-1.0-0 libpangoxft-1.0-0 libpciaccess0 libphodav-2.0-0 libphodav-2.0-common libpixman-1-0 libproxy1v5 \
    libpulse-mainloop-glib0 libpulse0 libpython-stdlib libgstreamer1.0-0 libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-vnc-2.0-0 \
    libgudev-1.0-0 libgvnc-1.0-0 libharfbuzz0b libibverbs1 libiec61883-0 libindicator3-7 libiscsi7 libjack-jackd2-0 libjbig0 \
    libjpeg-turbo8 libjpeg8 libjson-glib-1.0-0 libjson-glib-1.0-common liblcms2-2 libmp3lame0 libmpg123-0 libnetcf1 libnl-route-3-200 \
    libnspr4 libnss3 libogg0 libopus0 liborc-0.4-0 libosinfo-1.0-0 libcairo-gobject2 libcairo2 libcdparanoia0 libcolord2 libcroco3 \
    libcups2 libdatrie1 libdbusmenu-glib4 libdbusmenu-gtk3-4 libdconf1 libdv4 libegl-mesa0 libegl1 libepoxy0 libfdt1 libflac8 \
    libfontconfig1 libgbm1 libgdk-pixbuf2.0-0 libgdk-pixbuf2.0-bin libgdk-pixbuf2.0-common libglapi-mesa libglvnd0  libgraphite2-3 \
    libgstreamer-plugins-base1.0-0 libgstreamer-plugins-good1.0-0 gtk-update-icon-cache hicolor-icon-theme humanity-icon-theme \
    ibverbs-providers  libaa1 libaio1 libappindicator3-1 libasound2 libasound2-data libasyncns0 libatk-bridge2.0-0 libatk1.0-0 \
    libatk1.0-data libatspi2.0-0 libaugeas0 libavahi-client3 libavahi-common-data libavahi-common3 libavc1394-0 libbluetooth3 \
    libbrlapi0.6 libcaca0 libcacard0 gir1.2-atk-1.0 gir1.2-freedesktop gir1.2-gdkpixbuf-2.0 gir1.2-gtk-3.0 gir1.2-gtk-vnc-2.0 \
    gir1.2-libosinfo-1.0  gir1.2-pango-1.0 gir1.2-spiceclientglib-2.0 gir1.2-spiceclientgtk-3.0 gir1.2-vte-2.91 glib-networking \
    glib-networking-common glib-networking-services gsettings-desktop-schemas gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-x adwaita-icon-theme at-spi2-core augeas-lenses bridge-utils cpu-checker dconf-gsettings-backend dconf-service \
    fontconfig fontconfig-config fonts-dejavu-core genisoimage gir1.2-appindicator3-0.1 gir1.2-secret-1 -y
    # should be installed first
}

function install_virt_manager() {
    cd ${BUILDTMPDIR} || return

	rm -f "${BUILDTMPDIR}/task.virtmanager.done"

	virt_deps > /dev/null

    pip install pycairo
    pip3 install pycairo
    pip3 install PyGObject -U
    pip install PyGObject -U

        test ! -f "libvirt-glib-1.0.0.tar.gz" && wget https://libvirt.org/sources/glib/libvirt-glib-1.0.0.tar.gz
    if [ -f "libvirt-glib-1.0.0.tar.gz" ]
    then
        tar xf libvirt-glib-1.0.0.tar.gz
        cd libvirt-glib-1.0.0 || return
        aclocal && libtoolize --force
        automake --add-missing
        ./configure
        make -j$(nproc)
        #ToDo add blacklist
        checkinstall --pkgname=libvirt-glib-1.0-0 --default
        test ! -f gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb && wget http://launchpadlibrarian.net/297448356/gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb
        dpkg -i gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb

        /sbin/ldconfig
    fi

    if [ ! -d "virt-manager" ]; then
        #git clone -b v1.5-maint https://github.com/virt-manager/virt-manager.git
        git clone https://github.com/virt-manager/virt-manager.git
        echo "[+] Cloned Virt Manager repo"
    fi
    cd "virt-manager" || exit 1
    apt-get install gobject-introspection intltool pkg-config python-lxml python3-libxml2 libxml2-dev libxslt-dev python-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev -y
    # py3
    python3 setup.py build
    python3 setup.py install
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
	date > "${BUILDTMPDIR}/task.virtmanager.done"
    echo "[+] install virt-manager done"
}

function install_virt_viewer() {
    cd ${BUILDTMPDIR} || return

	rm -f "${BUILDTMPDIR}/task.virtviewer.done"

	virt_deps > /dev/null

    #pip install pycairo
    #pip3 install pycairo
    #pip3 install PyGObject -U
    #pip install PyGObject -U

	# https://www.spice-space.org/download.html

	test ! -f spice-protocol-0.12.15.tar.bz2 && wget https://www.spice-space.org/download/releases/spice-protocol-0.12.15.tar.bz2
	rm -rf spice-protocol-0.12.15
	tar xvfj spice-protocol-0.12.15.tar.bz2
	cd spice-protocol-0.12.15
		fail=0
        ./configure --prefix=/usr/local/spice-protocol || fail=$?
		if [ $fail -ne 0 ]
		then
			echo "[-] configure failed."
			exit $fail
		fi
		rm -rf /usr/local/spice-protocol
	make && make install


	test ! -f spice-gtk-0.36.tar.bz2 && wget https://www.spice-space.org/download/gtk/spice-gtk-0.36.tar.bz2
	rm -rf spice-gtk-0.36
	tar xvfj spice-gtk-0.36.tar.bz2
	cd spice-gtk-0.36
	bash
		fail=0
        ./configure --prefix=/usr/local/spice-gtk || fail=$?
		if [ $fail -ne 0 ]
		then
			echo "[-] configure failed."
			exit $fail
		fi



		test ! -f "virt-viewer-${virt_viewer_version}.tar.gz" && wget https://virt-manager.org/download/sources/virt-viewer/virt-viewer-${virt_viewer_version}.tar.gz
		rm -rf virt-viewer-${virt_viewer_version}
        tar xf virt-viewer-${virt_viewer_version}.tar.gz
        cd virt-viewer-${virt_viewer_version}
		apt-get install gobject-introspection intltool pkg-config python-lxml python3-libxml2 libxml2-dev libxslt-dev python-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev libgtk-vnc-2.0-dev libspice-client-gtk-3.0-dev -y >/dev/null

		#cat configure.ac | grep -q 'SPICE_GTK_REQUIRED="0.34"' || sed -i -E 's/SPICE_GTK_REQUIRED="0.3[2345]"/SPICE_GTK_REQUIRED="0.34"/g' configure configure.ac 
		#cat configure.ac | grep 'SPICE_GTK_REQUIRED=' || true

        #./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/${QTARGETS} --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-kvm  --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-libssh2 --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone || fail=$?
		fail=0
        ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc/virt-viewer --sharedstatedir=/usr/share/virt-viewer --with-gtk-vnc --with-spice-gtk --with-ovirt || fail=$?
		if [ $fail -ne 0 ]
		then
			echo "[-] configure failed."
			exit $fail
		fi
		filelist=`grep -R '/missing aclocal-1.16' * | awk -F':' '{print $1}'`;sed -i -e 's/missing aclocal-1.16/missing aclocal-1.15/g' $filelist || true
		filelist=`grep -R '/missing automake-1.16' * | awk -F':' '{print $1}'`;sed -i -e 's/missing automake-1.16/missing automake-1.15/g' $filelist || true
		make -j`nproc`

		bash

		exit 0

        aclocal && libtoolize --force
        automake --add-missing
        ./configure
        make -j$(nproc)
        #ToDo add blacklist
        checkinstall --pkgname=libvirt-glib-1.0-0 --default
        test ! -f gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb && wget http://launchpadlibrarian.net/297448356/gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb
        dpkg -i gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb

        /sbin/ldconfig

		exit $?

    cd "virt-manager" || exit 1
    apt-get install gobject-introspection intltool pkg-config python-lxml python3-libxml2 libxml2-dev libxslt-dev python-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev -y
    # py3
    python3 setup.py build
    python3 setup.py install
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
	date > "${BUILDTMPDIR}/task.virtviewer.done"
    echo "[+] install virt-viewer done"
}

function install_kvm_linux_apt() {

    kvm-ok

    # Ubuntu 18.04:
    # /dev/kvm permissions always changed to root after reboot
    # "chown root:libvirt /dev/kvm" doesnt help
    grep -q '^kvm:' /etc/group || addgroup kvm
    usermod -a -G kvm "$(whoami)"
    if [ ! -z "$username" ]; then
        usermod -a -G kvm "$username" || true
    fi
    chgrp kvm /dev/kvm
    if [ ! -f /etc/udev/rules.d/50-qemu-kvm.rules ]; then
        echo 'KERNEL=="kvm", GROUP="kvm", MODE="0660"' >> /etc/udev/rules.d/50-qemu-kvm.rules
    fi
}


function replace_qemu_clues_public() {
    echo '[+] Patching QEMU clues'
    _sed_aux 's/QEMU HARDDISK/DavidMortals HARDDISK/g' qemu*/hw/ide/core.c 'QEMU HARDDISK was not replaced in core.c'
    _sed_aux 's/QEMU HARDDISK/DavidMortals HARDDISK/g' qemu*/hw/scsi/scsi-disk.c 'QEMU HARDDISK was not replaced in scsi-disk.c'
    _sed_aux 's/QEMU DVD-ROM/DavidMortals DVD-ROM/g' qemu*/hw/ide/core.c 'QEMU DVD-ROM was not replaced in core.c'
    _sed_aux 's/QEMU DVD-ROM/DavidMortals DVD-ROM/g' qemu*/hw/ide/atapi.c 'QEMU DVD-ROM was not replaced in atapi.c'
    _sed_aux 's/QEMU PenPartner tablet/DavidMortals PenPartner tablet/g' qemu*/hw/usb/dev-wacom.c 'QEMU PenPartner tablet'
    _sed_aux 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("DavidMortals");/g' qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux 's/QEMU CD-ROM/DavidMortals CD-ROM/g' qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "DavidMortals");/g'  qemu*/hw/ide/atapi.c 'padstr was not replaced in atapi.c'
    _sed_aux 's/QEMU MICRODRIVE/DavidMortals MICRODRIVE/g' qemu*/hw/ide/core.c 'QEMU MICRODRIVE was not replaced in core.c'
    _sed_aux 's/KVMKVMKVM\\0\\0\\0/GenuineIntel/g' qemu*/target/i386/kvm.c 'QEMU MICRODRIVE was not replaced in core.c'
    _sed_aux 's/KVMKVMKVM\\0\\0\\0/GenuineIntel/g' qemu*/target/i386/kvm.c 'KVMKVMKVM was not replaced in kvm.c'
    _sed_aux 's/"bochs"/"hawks"/g' qemu*/block/bochs.c 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'
    # depricated
    #_sed_aux 's/Microsoft Hv/GenuineIntel/g' qemu*/target/i386/kvm.c 'Microsoft Hv was not replaced in target/i386/kvm.c'
    #_sed_aux 's/Bochs\/Plex86/DavidMortals\/FIRM64/g' qemu*/roms/vgabios/vbe.c 'BOCHS was not replaced in roms/vgabios/vbe.c'
}

function replace_seabios_clues_public() {
    echo "[+] Generating SeaBios Kconfig"
    echo "[+] Fixing SeaBios antivms"
    _sed_aux 's/Bochs/DavidMortals/g' src/config.h 'Bochs was not replaced in src/config.h'
    _sed_aux 's/BOCHSCPU/DavidMortals/g' src/config.h 'BOCHSCPU was not replaced in src/config.h'
    _sed_aux 's/"BOCHS "/"DavidMortals"/g' src/config.h 'BOCHS was not replaced in src/config.h'
    _sed_aux 's/BXPC/DavidMortals/g' src/config.h 'BXPC was not replaced in src/config.h'
    _sed_aux 's/QEMU0001/DavidMortals/g' src/fw/ssdt-misc.dsl 'QEMU0001 was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/QEMU\/Bochs/DavidMortals\/DavidMortals/g' vgasrc/Kconfig 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'
    _sed_aux 's/qemu /DavidMortals /g' vgasrc/Kconfig 'qemu was not replaced in vgasrc/Kconfig'

    FILES=(
        src/hw/blockcmd.c
        src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"QEMU/"DavidMortals/g' "$file" "QEMU was not replaced in $file"
    done

    _sed_aux 's/"QEMU"/"DavidMortals"/g' src/hw/blockcmd.c '"QEMU" was not replaced in  src/hw/blockcmd.c'

    FILES=(
        "src/fw/acpi-dsdt.dsl"
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"BXPC"/"DavidMortals"/g' "$file" "BXPC was not replaced in $file"
    done
    _sed_aux 's/"BXPC"/"DavidMortals"/g' "src/fw/ssdt-pcihp.dsl" 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'
    _sed_aux 's/"BXDSDT"/"DavidMortals"/g' "src/fw/ssdt-pcihp.dsl" 'BXDSDT was not replaced in src/fw/ssdt-pcihp.dsl'
    _sed_aux 's/"BXPC"/"DavidMortals"/g' "src/fw/ssdt-proc.dsl" 'BXPC was not replaced in "src/fw/ssdt-proc.dsl"'
    _sed_aux 's/"BXSSDT"/"DavidMortals"/g' "src/fw/ssdt-proc.dsl" 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'
    _sed_aux 's/"BXPC"/"DavidMortals"/g' "src/fw/ssdt-misc.dsl" 'BXPC was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDTSU"/"DavidMortals"/g' "src/fw/ssdt-misc.dsl" 'BXDSDT was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDTSUSP"/"DavidMortals"/g' src/fw/ssdt-misc.dsl 'BXSSDTSUSP was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDT"/"DavidMortals"/g' src/fw/ssdt-proc.dsl 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'
    _sed_aux 's/"BXSSDTPCIHP"/"DavidMortals"/g' src/fw/ssdt-pcihp.dsl 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'

    FILES=(
        src/fw/q35-acpi-dsdt.dsl
        src/fw/acpi-dsdt.dsl
        src/fw/ssdt-misc.dsl
        src/fw/ssdt-proc.dsl
        src/fw/ssdt-pcihp.dsl
        src/config.h
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"BXPC"/"A M I"/g' "$file" "BXPC was not replaced in $file"
    done
}

function qemu_func() {
	rm -f "${BUILDTMPDIR}/task.qemu.done"
    if [ -z "$(which pip)" ]
    then
        echo "command pip not found, try to install it first (apt install python-pip)"
        apt install python-pip -y || exit $?
    fi

    pip install sphinx >/dev/null

    if [ "$OS" = "Linux" ]; then
        apt-get install checkinstall openbios-* libssh2-1-dev vde2 liblzo2-dev libghc-gtk3-dev libsnappy-dev libbz2-dev libxml2-dev google-perftools libgoogle-perftools-dev libvde-dev -y >/dev/null
        apt-get install debhelper ibusb-1.0-0-dev libxen-dev uuid-dev xfslibs-dev libjpeg-dev libusbredirparser-dev device-tree-compiler texinfo libbluetooth-dev libbrlapi-dev libcap-ng-dev libcurl4-gnutls-dev libfdt-dev gnutls-dev libiscsi-dev libncurses5-dev libnuma-dev libcacard-dev librados-dev librbd-dev libsasl2-dev libseccomp-dev libspice-server-dev \
        libaio-dev libcap-dev libattr1-dev libpixman-1-dev libgtk2.0-bin  libxml2-utils systemtap-sdt-dev texinfo -y >/dev/null
        # qemu docs required
        echo "" | perl -MCPAN -e install "Perl/perl-podlators"

    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew install pkg-config libtool jpeg gnutls glib ncurses pixman libpng vde gtk+3 libssh2 libssh2 libvirt snappy libcapn gperftools glib -y
    fi

    cd ${BUILDTMPDIR} || exit 1

    echo '[+] Downloading QEMU source code'
    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        wget "https://download.qemu.org/qemu-$qemu_version.tar.xz"
        rm -f qemu-$qemu_version.tar.xz.sig
        wget "https://download.qemu.org/qemu-$qemu_version.tar.xz.sig"
    fi
    gpg --list-keys CEACC9E15534EBABB82D3FA03353C9CEF108B584 || gpg --keyserver pool.sks-keyservers.net --recv-keys CEACC9E15534EBABB82D3FA03353C9CEF108B584 || true
    gpg --verify "qemu-$qemu_version.tar.xz.sig"

    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        echo "[-] Download qemu-$qemu_version failed"
        exit
    fi

    if ! tar xf "qemu-$qemu_version.tar.xz" ; then
        echo "[-] Failed to extract, check if download was correct"
        exit 1
    fi

    # WOOT
    # some checks may be depricated, but keeping them for compatibility with old versions

    #if [ $? -eq 0 ]; then
        if declare -f -F "replace_qemu_clues"; then
            replace_qemu_clues
        else
            replace_qemu_clues_public
        fi
        # ToDo reintroduce it?
        #if [ $fail -eq 0 ]; then
            echo '[+] Starting compile it'
            cd qemu-$qemu_version || return
            # add in future --enable-netmap https://sgros-students.blogspot.com/2016/05/installing-and-testing-netmap.html
            # remove --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  if you want all targets
            fail=0
            if [ "$OS" = "Linux" ]; then
                # --enable-sparse
                QTARGETS=" --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user"
                if [ ! -z "$QEMU_TARGERS" ]; then
                    QTARGETS=" --target-list={$QEMU_TARGERS}"
                fi
                if [ "$QEMU_TARGERS" = "ALL" -o "$QEMU_TARGERS" = "all" ]; then
                    QTARGETS=""
                fi
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/${QTARGETS} --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-kvm  --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-libssh2 --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone || fail=$?
            elif [ "$OS" = "Darwin" ]; then
                # --enable-vhost-net --enable-vhost-crypto
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --enable-gnutls --enable-docs  --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-hax --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool  --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone || fail=$?
            fi
            if  [ $fail -eq 0 ]; then
                echo '[+] Starting Install it'
                #dpkg -i qemu*.deb
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                make -j$(nproc)
        fail=0
                if [ "$OS" = "Linux" ]; then
            echo '[+] Cleaning QEMU old install if exists'
                    rm -r /usr/share/qemu >/dev/null 2>&1
                    dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
                        oldpkgs="$(dpkg -l |grep qemu |cut -d ' ' -f 3)"
                        echo "[-] removinge old qemu packages: $oldpkgs ..."
                        test -z "$oldpkgs" || echo "$oldpkgs" | xargs apt purge -y >/dev/null 
						apt purge -y sgabios >/dev/null || true
                
                    checkinstall -D --pkgname=qemu-$qemu_version --nodoc --showinstall=no --default || fail=$?
                        dpkg -l | grep '^ii' | grep -q "qemu-$qemu_version" || fail=$?
                elif [ "$OS" = "Darwin" ]; then
                    make -j$(nproc) install || fail=$?
                fi
                echo $fail
                if  [ $fail -eq 0 ]; then
                    echo '[+] Patched, compiled and installed'
                else
                    echo '[-] Install failed'
                        exit $fail
                fi
                # hack for libvirt/virt-manager
                if [ ! -f /usr/bin/qemu-system-x86_64-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                fi
                if [ ! -f /usr/bin/kvm-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                fi
                if [ ! -f /usr/bin/kvm ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                
                if [ -z "$(grep -E '^tss:' /etc/group)" ]; then
                    groupadd "tss"
                    useradd -g "tss" "tss"
                    echo "[+] Creating Group and User: tss"
                else
                    echo "[?] tss Group and User exist, skip"
                fi
            else
                echo '[-] Compilling failed'
                exit 1
            fi
        #else
        #    echo '[-] Check previous output'
        #    exit
        #fi

    #else
    #    echo '[-] Download QEMU source was not possible'
    #fi
    if [ "$OS" = "linux" ]; then
        dpkg --get-selections | grep "qemu" | xargs apt-mark hold
        dpkg --get-selections | grep "libvirt" | xargs apt-mark hold
        # apt-mark unhold qemu
    fi
	date > "${BUILDTMPDIR}/task.qemu.done"
}

function seabios_func() {
        echo "disabled for bug: Makefile:253: recipe for target 'src/fw/ssdt-misc.hex' failed" && return 0
    cd ${BUILDTMPDIR} || return
    fail=0
    echo '[+] Installing SeaBios dependencies'
    apt-get install git iasl -y
    if [ -d seabios ]; then
        rm -r seabios
    fi
    if git clone https://github.com/coreboot/seabios.git; then
        cd seabios || return
        # git checkout -b 1.12-stable remotes/origin/1.12-stable
        if declare -f -F "replace_seabios_clues"; then
            replace_seabios_clues
        else
            replace_seabios_clues_public
        fi
        # make help
        # make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
        # get rid of this hack
        make -j $(nproc) 2>/dev/null
        # Windows 10(latest rev.) is uninstallable without ACPI_DSDT
        # sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
        sed -i 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config
        if make -j $(nproc); then
            echo '[+] Replacing old bios.bin to new out/bios.bin'
            bios=0
            FILES=(
                "/usr/share/qemu/bios.bin"
                "/usr/share/qemu/bios-256k.bin"
            )
            for file in "${FILES[@]}"; do
                cp -vf out/bios.bin "$file"
                bios=1
            done
            if [ $bios -eq 1 ]; then
                echo '[+] Patched bios.bin placed correctly'
            else
                echo '[-] Bios patching failed'
            fi
        else
            echo '[-] Bios compilation failed'
                exit 1
        fi
        cd - || return
    else
        echo '[-] Check if git installed or network connection is OK'
    fi
}

function issues(){
cat << EndOfHelp
### Links:
    * https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-troubleshooting-common_libvirt_errors_and_troubleshooting

### Errors and Solutions
    * Error:
        * If you getting an apparmor error
    * Solution
        * sed -i 's/#security_driver = "apparmor"/security_driver = "none"/g' /etc/libvirt/qemu.conf

    * Error:
        * Libvirt sometimes causes access denied errors with access the locations different from "/var/lib/libvirt/images"
    * Solution:
        * sed -i 's/user = "root"/user = "$(whoami)"/g' /etc/libvirt/qemu.conf
        * sed -i 's/user = "root"/group = "libvirt"/g' /etc/libvirt/qemu.conf

    * Error:
        required by /usr/lib/libvirt/storage-file/libvirt_storage_file_fs.so
    * Solution:
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service

    * Error:
        /libvirt.so.0: version LIBVIRT_PRIVATE_x.x.0' not found (required by /usr/sbin/libvirtd)
    * Solutions:
        1. apt-get purge libvirt0 libvirt-bin
        2. reboot
        3. $0 libvirt

        Can be extra help, but normally solved with first3 steps
        1. ldd /usr/sbin/libvirtd
        2. ls -lah /usr/lib/libvirt*
            * Make sure what all symlinks pointing to last version

    * Error:
        libvirt: Polkit error : authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'
    * Solutions:
        1.
            sed -i 's/#unix_sock_group/unix_sock_group/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' /etc/libvirt/libvirtd.conf
        2. Add ssh key to $HOME/.ssh/authorized_keys
            virt-manager -c "qemu+ssh://user@host/system?socket=/var/run/libvirt/libvirt-sock"

    * Slow HDD/Snapshot taking performance?
        Modify
            <driver name='qemu' type='qcow2'/>
        To
            <driver name='qemu' type='qcow2' cache='none' io='native'/>
    * Error:
        error : virPidFileAcquirePath:422 : Failed to acquire pid file '/var/run/libvirtd.pid': Resource temporarily unavailable
    * Solution
        ps aux | grep libvirtd
    * Error:
        Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied
    * Solution:
        * usermod -G libvirt -a username
        * log out and log in

    # Fixes from http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    1. ImportError: No module named libvirt
    $ ./kvm-qemu.sh libvirt

    2. ImportError: No module named libxml2
    $ apt-get install python-libxml2 python3-libxml2

    3. ImportError: No module named requests
    $ apt-get install python-requests

    4. Error launching details: Namespace GtkVnc not available
    $ ./kvm-qemu.sh libvirt

    5. ValueError: Namespace LibvirtGLib not available
    $ ./kvm-qemu.sh libvirt

    6. ValueError: Namespace Libosinfo not available
    $ apt-get install libosinfo-1.0

    7. ImportError: No module named ipaddr
    $ apt-get install python-ipaddr

    8. Namespace Gtk not available: Could not open display: localhost:10.0
    $ apt-get install libgtk-3-dev

    9. ImportError: cannot import name Vte
    $ apt-get install gir1.2-vte-2.90

EndOfHelp
}

function install_WebVirtCloud(){
    apt-get -y install git virtualenv python-virtualenv python-dev python-lxml libvirt-dev zlib1g-dev libxslt1-dev nginx supervisor libsasl2-modules gcc pkg-config python-guestfs
    git clone https://github.com/retspen/webvirtcloud
    cd webvirtcloud || return
    cp webvirtcloud/settings.py.template webvirtcloud/settings.py
    # now put secret key to webvirtcloud/settings.py
    cp conf/supervisor/webvirtcloud.conf /etc/supervisor/conf.d
    cp conf/nginx/webvirtcloud.conf /etc/nginx/conf.d
    cd ..
    mv webvirtcloud /srv
    chown -R www-data:www-data /srv/webvirtcloud
    cd /srv/webvirtcloud || return
    virtualenv venv
    source venv/bin/activate
    sed -i 's/libvirt-python//g' conf/requirements.txt
    pip install -r conf/requirements.txt
    python manage.py migrate
    chown -R www-data:www-data /srv/webvirtcloud
    rm /etc/nginx/sites-enabled/default
    service nginx restart
    service supervisor restart
}

function cloning() {
    if [ $# -lt 5 ]; then
        echo '[-] You must provide <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_base>'
        exit 1
    fi
    for i in $(seq "$3" "$4"); do
        worked=1
        # bad macaddress can be generated
        while [ $worked -eq 1 ]; do
            macaddr=$(hexdump -n 6 -ve '1/1 "%.2x "' /dev/random | awk -v a="2,6,a,e" -v r="$RANDOM" 'BEGIN{srand(r);}NR==1{split(a,b,",");r=int(rand()*4+1);printf "%s%s:%s:%s:%s:%s:%s\n",substr($1,0,1),b[r],$2,$3,$4,$5,$6}') 2>/dev/null
            #virt-clone --print-xml -n $1_$i -o $1 -m "$macaddr"
            if [ ! -f "${5}/${1}_${i}.qcow2" ]; then
                #Linked snapshots are disabled due to performance problems
                #qemu-img create -f qcow2 -b "$2" "$5/$1_$i.qcow2"
                #rsync -ahW --no-compress --progress "$2" "$5/$1_$i.qcow2"
                echo "Creating $5/$1_$i.qcow2"
                cp "$2" "$5/$1_$i.qcow2"
            fi
            #2>/dev/null
            if virt-clone --print-xml -n "$1_$i" -o "$1" -m "$macaddr" |sed "s|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" io=\"native\"/>|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" io=\"native\"/>\\n      <source file=\"${5}/${1}_${i}.qcow2\"/>|g" > "$5/$1_$i.xml"; then
                sed -i "s|<domain type='kvm'>|<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>|g" "$5/$1_$i.xml"
                virsh define "$5/$1_$i.xml"
                worked=0
            fi
        done
        echo "<host mac='$macaddr' name='$1_$i' ip='$6.$i+1'/>"
    done

    echo "[+] Enjoy"

}

# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[:upper:]" "[:lower:]")

test -z "$COMMAND" && COMMAND="-h"

case $COMMAND in
    '-h')
        usage
        exit 0;;
    'issues')
        issues
        exit 0;;
esac

if [ -n "$2" ]
then
    username="$2"
    if [ -n "$(id -u $username 2>/dev/null)" ]; then
        test "$(id -u $username)" != 0 && echo "[+] Install for non-root user $username"
    else
        echo "[-] username $username doesn't exist"
        exit 1
    fi
fi

#check if start with root
if [ "$EUID" -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi
if [ "$HOME" != "/root" ]
then
   echo 'This script must be run as root, if you are run by please use -H'
   exit 1
fi

OS="$(uname -s)"
#add-apt-repository universe
#apt-get update && apt-get upgrade
#make

export BUILDTMPDIR="${HOME}/tmp/qemubuild/"

mkdir -p ${BUILDTMPDIR}

function apt_pkg_init()
{
    echo "[+] apt updating ..."
    add-apt-repository universe >/dev/null
    sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    apt-get update >/dev/null
    
    apt --fix-broken install -y >/dev/null
    
    apt-get build-dep qemu qemu-system-x86 qemu-kvm -y >/dev/null
    dpkg -l | grep "^ii" | grep -q "language-pack-en" || apt-get install language-pack-en -y
    dpkg -l | grep "^ii" | grep -q "libnfs-dev" || apt-get install libnfs-dev -y
    dpkg -l | grep "^ii" | grep -q "libiscsi-dev" || apt-get install libiscsi-dev-dev -y
    dpkg -l | grep "^ii" | grep -q "apparmor-utils" || apt-get install apparmor-utils -y

    apt-get install build-essential python-pip python3-pip gcc pkg-config cpu-checker intltool -y >/dev/null
    apt-get install gtk-update-icon-cache -y >/dev/null

    # WSL support
    apt-get install gcc make gnutls-bin -y >/dev/null
    # remove old
    # apt-get purge libvirt0 libvirt-bin -y >/dev/null
}

# return 0 for at least one task pending, or return 1 for all tasks are done
function pending_task_func()
{
    local tasks="$@"
    local item=""
    local chkcnt=0
    for item in $tasks
    do
        case "$item" in
'qemu')
            debfiles="$(ls -A ${BUILDTMPDIR}/qemu-$qemu_version/qemu-${qemu_version}*.deb 2>/dev/null || true)"
            if [ -n "$debfiles" -a -f "${BUILDTMPDIR}/task.${item}.done" ]
            then
                echo "[+] $item already compiled."
                echo "$debfiles"
                echo "[-] remove ${BUILDTMPDIR}/task.${item}.done file for re-build"
                continue
            fi
            let chkcnt=$chlcnt+1
        ;;
'libvirt')
            debfiles="$(ls -A ${BUILDTMPDIR}/libvirt-$libvirt_version/libvirt-${libvirt_version}*.deb 2>/dev/null || true)"
            if [ -n "$debfiles" -a -f "${BUILDTMPDIR}/task.${item}.done" ]
            then
                echo "[+] $item already compiled."
                echo "$debfiles"
                echo "[-] remove ${BUILDTMPDIR}/task.${item}.done file for re-build"
                continue
            fi
            let chkcnt=$chkcnt+1
        ;;
'virtmanager')
            if [ -f "${BUILDTMPDIR}/task.${item}.done" ]
            then
                echo "[+] $item already compiled."
                echo "[-] remove ${BUILDTMPDIR}/task.${item}.done file for re-build"
                continue
            fi
            let chkcnt=$chkcnt+1
        ;;
'virtviewer')
            debfiles="$(ls -A ${BUILDTMPDIR}/qemu-$qemu_version/qemu-${qemu_version}*.deb 2>/dev/null || true)"
            if [ -n "$debfiles" -a -f "${BUILDTMPDIR}/task.${item}.done" ]
            then
                echo "[+] $item already compiled."
                echo "$debfiles"
                echo "[-] remove ${BUILDTMPDIR}/task.${item}.done file for re-build"
                continue
            fi
            let chkcnt=$chkcnt+1
        ;;
*)
            let chkcnt=$chkcnt+1
            echo "[-] unknown task: $item"
        ;;
        esac
    done
    if [ $chkcnt -ne 0 ]
    then
		apt_pkg_init
        return 0
    fi
	echo "[+] All tasks is done: $tasks"
    exit 0
}
case "$COMMAND" in
'all')
    pending_task_func qemu kvm virtmanager virtviewer libguestfs tcp_bbr grub
	;;
*)
    pending_task_func "$COMMAND"
	;;
esac

case "$COMMAND" in
'all')
    qemu_func
    seabios_func
    if [ "$OS" = "Linux" ]; then
		install_libvirt
        install_kvm_linux_apt
        install_libguestfs
        install_virt_manager
        install_virt_viewer
        # check if all features enabled
        virt-host-validate
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service
        _enable_tcp_bbr
        grub_iommu
    elif [ "$OS" = "Darwin" ]; then
        install_haxm_mac
    fi
    ;;
'qemu')
    qemu_func;;
'seabios')
    seabios_func;;
'kvm')
	$0 libvirt || true
    install_kvm_linux_apt;;
'haxm')
    install_haxm_mac;;
'libguestfs')
    install_libguestfs;;
'tcp_bbr')
    _enable_tcp_bbr;;
'replace_qemu')
    if declare -f -F "replace_qemu_clues"; then
        replace_qemu_clues
    else
        replace_qemu_clues_public
    fi
    ;;
'libvirt')
    install_libvirt;;
'libvmi')
    install_libvmi;;
'virtmanager')
	$0 libvirt || true
    install_virt_manager;;
'virtviewer')
	$0 libvirt || true
    install_virt_viewer;;
'clone')
    cloning "$2" "$3" "$4" "$5" "$6" "$7";;
'noip')
    if [ "$OS" = "Linux" ]; then
        cd ${BUILDTMPDIR} || return
        test ! -f noip-duc-linux.tar.gz && wget http://www.no-ip.com/client/linux/noip-duc-linux.tar.gz
        tar xf noip-duc-linux.tar.gz
        #rm noip-duc-linux.tar.gz
        cd "noip-*" || return
        make install
        crontab -l | { cat; echo "@reboot sleep 10 && /usr/local/bin/noip2 -c /usr/local/etc/no-ip2.conf"; } | crontab -
    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew cask install no-ip-duc
    fi
    ;;
'replace_seabios')
    if [ ! -d "$2" ]; then
        echo "[-] Pass the path to SeaBios folder"
        exit 1
    fi
    cd "$2" || exit 1
    if declare -f -F "replace_seabios_clues"; then
        replace_seabios_clues
    else
        replace_seabios_clues_public
    fi
    cd - || exit 0
    ;;
'changelog')
    changelog;;
'webvirtmgr')
    install_WebVirtCloud;;
'grub')
    grub_iommu;;
'mosh')
    if [ "$OS" = "Linux" ]; then
        apt-get install mosh -y
    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew install mosh
    else
        echo "https://mosh.org/#getting"
    fi
    ;;
*)
    usage;;
esac

echo "[+] all finished"

