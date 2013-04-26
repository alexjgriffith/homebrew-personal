require 'formula'

class Dovecot2 < Formula
  url 'http://dovecot.org/releases/2.0/dovecot-2.0.13.tar.gz'
  homepage 'http://dovecot.org/'
  md5 'fd8a0702275a61332db7353dadff0f92'

  skip_clean 'sbin/dovecot'
  skip_clean 'bin/dsync'
  skip_clean 'bin/doveconf'
  skip_clean 'bin/doveadm'
  skip_clean 'lib/dovecot/auth'

  def install
    system "./configure", "--disable-dependency-tracking", "--prefix=#{prefix}", "--sysconfdir=#{etc}", "--localstatedir=#{var}", "--with-ssl=openssl"
    system "make install"
    (prefix + "org.dovecot.plist").write startup_plist
  end

  def caveats; <<-EOS
For Dovecot to work, you will need to do the following:

1) Create configuration in #{etc}

2) If required by the configuration above, create a dovecot user and group

3) possibly create a launchd item:
      sudo cp #{prefix}/org.dovecot.plist /Library/LaunchDaemons
      sudo launchctl load -w /Library/LaunchDaemons/org.dovecot.plist

Source: http://wiki.dovecot.org/LaunchdInstall
4) start the server using:
      sudo launchctl load /Library/LaunchDaemons/org.dovecot.plist
    EOS
  end

  def startup_plist; <<-EOS.undent
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
            <key>Label</key>
            <string>org.dovecot</string>
            <key>OnDemand</key>
            <false/>
            <key>ProgramArguments</key>
            <array>
                    <string>#{sbin}/dovecot</string>
                    <string>-F</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>ServiceDescription</key>
            <string>Dovecot mail server</string>
    </dict>
    </plist>
    EOS
  end
end
