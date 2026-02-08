FROM ubuntu:24.04

# Install necessary packages
RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user for the challenge
RUN useradd -m -u 1001 ctf

# Set working directory
WORKDIR /home/ctf

# Copy the binary
COPY vuln /home/ctf/vuln

# Create flag file (not visible in binary!)
RUN echo "LNMHACKS{h34p_func710n_p01n73r_h1j4ck}" > /home/ctf/flag.txt

# Set permissions
RUN chmod +x /home/ctf/vuln && \
    chmod 644 /home/ctf/flag.txt && \
    chown -R root:root /home/ctf && \
    chmod 755 /home/ctf

# Expose port
EXPOSE 3015
# Run the challenge with socat
CMD ["socat", "TCP-LISTEN:3015,reuseaddr,fork", "EXEC:/home/ctf/vuln"]
