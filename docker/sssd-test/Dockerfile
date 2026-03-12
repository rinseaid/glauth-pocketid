FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ldap-utils \
    sssd \
    sssd-ldap \
    sssd-tools \
    libnss-sss \
    libpam-sss \
    libsss-sudo \
    openssh-server \
    openssh-client \
    sudo \
    procps \
    zsh \
    && rm -rf /var/lib/apt/lists/*

COPY sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf

# Create run directories
RUN mkdir -p /var/run/sssd /run/sshd

# Configure NSS to use sss
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf && \
    echo "sudoers:        files sss" >> /etc/nsswitch.conf

# Configure SSH to use SSSD for authorized keys
RUN echo "" >> /etc/ssh/sshd_config && \
    echo "# SSSD SSH key delivery" >> /etc/ssh/sshd_config && \
    echo "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u" >> /etc/ssh/sshd_config && \
    echo "AuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

# Generate SSH host keys
RUN ssh-keygen -A

# Configure PAM to auto-create home directories on first login
RUN echo "session optional pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# Test scripts
COPY test.sh /test.sh
COPY test-sssd.sh /test-sssd.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /test.sh /test-sssd.sh /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
