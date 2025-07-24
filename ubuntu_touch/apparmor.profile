#include <tunables/global>

leitungs.client {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>
  #include <abstractions/audio>
  #include <abstractions/ubuntu-touch>

  # Allow execution from cloned git repository
  /home/*/leitung/ubuntu_touch/client_ubuntu_touch.py ix,
  /home/*/leitung/ubuntu_touch/Phonebook.qml r,
  /home/*/leitung/ubuntu_touch/*.pem r,

  # Python interpreter and libraries
  /usr/bin/python3 ix,
  /usr/bin/python3.* ix,
  /usr/lib/python3.*/** mr,
  /usr/local/lib/python3.*/** mr,

  # Data files (relative to git repo)
  /home/*/leitung/ubuntu_touch/client_name.txt rwk,
  /home/*/leitung/ubuntu_touch/client_id.txt rwk,
  /home/*/leitung/ubuntu_touch/server_public_key.pem r,
  /home/*/leitung/ubuntu_touch/phonebook_cache.json rwk,
  
  # Network access (required for VoIP)
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /run/resolvconf/resolv.conf r,

  # Audio access (expanded for Ubuntu Touch)
  /dev/snd/** rw,
  /dev/audio* rw,
  /dev/dsp* rw,
  /dev/urandom r,
  /sys/devices/virtual/sound/** r,
  /proc/asound/** r,

  # DBus access (expanded for Ubuntu Touch)
  #include <abstractions/dbus-session>
  dbus send,
  dbus receive,
  dbus bind bus=session name=com.ubuntu.LeitungsClient,

  # Crypto libraries (expanded)
  /usr/lib/*/libssl.so* mr,
  /usr/lib/*/libcrypto.so* mr,
  /usr/lib/*/libstun*.so* mr,
  /usr/lib/*/libgcrypt*.so* mr,
  /usr/lib/*/libgpg-error*.so* mr,

  # Qt/QML libraries (expanded for Ubuntu Touch)
  /{usr,}/lib/*/libQt5*.so* mr,
  /{usr,}/lib/*/libqml*.so* mr,
  /usr/lib/*/qt5/** mr,
  /usr/lib/*/qt5/qml/** mr,
  /usr/share/qt5/** r,
  /usr/lib/@{multiarch}/qt5/** mr,

  # PyAudio and ALSA dependencies (expanded)
  /usr/share/alsa/** r,
  /etc/alsa/** r,
  /usr/lib/*/libasound.so* mr,
  /usr/lib/*/alsa-lib/** mr,
  /usr/lib/@{multiarch}/alsa-lib/** mr,

  # Temporary files (expanded)
  /tmp/** rwk,
  /var/tmp/** rwk,
  /home/*/leitung/ubuntu_touch/tmp/** rwk,
  owner @{HOME}/.cache/LeitungsClient/** rwk,

  # Debugging and logging
  /home/*/leitung/ubuntu_touch/debug.log w,
  /var/log/syslog r,
  owner /var/log/LeitungsClient.log w,
  
  # STUN/TURN client access (expanded)
  /etc/resolv.conf r,
  /etc/gai.conf r,
  /etc/services r,

  # Required for M2Crypto and crypto operations
  /proc/*/maps r,
  /proc/cpuinfo r,
  owner /dev/crypto rw,
  owner /dev/random rw,
  owner /dev/urandom rw,

  # Ubuntu Touch specific paths
  /usr/share/ubuntu-ui-toolkit/** r,
  /usr/lib/@{multiarch}/ubuntu-application-api/** mr,
  /usr/share/pyshared/** r,
}
