# AppArmor profile for Phonebook Secure VoIP Client, "client_ubuntu_touch.py"
# Profile name: leitungs.client
# Path:/home * ./leitung/ubuntu_touch/apparmor.profile
# For local development from git clone location
#git clone ->
#source: https://github.com/jon1enforce/leitung/ubuntu_touch.git

#include <tunables/global>

leitungs.client {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  # Allow execution from cloned git repository
  /home/*/leitung/ubuntu_touch/client_ubuntu_touch.py ix,
  /home/*/leitung/ubuntu_touch/Phonebook.qml r,
  /home/*/leitung/ubuntu_touch/*.pem r,

  # Python interpreter
  /usr/bin/python3 ix,
  /usr/bin/python3.* ix,

  # Data files (relative to git repo)
  /home/*/leitung/ubuntu_touch/client_name.txt rwk,
  /home/*/leitung/ubuntu_touch/client_id.txt rwk,
  /home/*/leitung/ubuntu_touch/server_public_key.pem r,
  
  # Network access (required for VoIP)
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,

  # Audio access
  /dev/snd/* rw,
  /dev/audio* rw,
  /dev/dsp* rw,
  /dev/urandom r,

  # DBus access
  #include <abstractions/dbus-session>
  dbus send,
  dbus receive,

  # Crypto libraries
  /usr/lib/*/libssl.so* mr,
  /usr/lib/*/libcrypto.so* mr,
  /usr/lib/*/libstun*.so* mr,

  # Qt/QML libraries
  /{usr,}/lib/*/libQt5*.so* mr,
  /{usr,}/lib/*/libqml*.so* mr,
  /usr/lib/*/qt5/** mr,

  # PyAudio dependencies
  /usr/share/alsa/** r,
  /etc/alsa/** r,
  /usr/lib/*/libasound.so* mr,

  # Temporary files
  /tmp/** rwk,
  /home/*/leitung/ubuntu_touch/tmp/** rwk,

  # Debugging output
  /home/*/leitung/ubuntu_touch/debug.log w,
  
  # STUN/TURN client access
  /etc/resolv.conf r,
}
