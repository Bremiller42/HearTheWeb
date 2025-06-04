# HearTheWeb

HearTheWeb plays short stereo tones whenever TCP or UDP packets are seen on the network. The tone frequency and stereo channel indicate the protocol and whether the packet is upstream or downstream.

## Usage

```bash
python main.py [--prefix PREFIX] [--interface INTERFACE] [--volume V] \
    [--sample-rate RATE] [--duration SECONDS] [--concurrency N]
```

- `--prefix` sets the IP prefix considered "local" (default `192.168.`).
- `--interface` chooses the network interface to sniff.
- `--volume` controls tone playback volume.
- `--sample-rate` and `--duration` tune audio characteristics.
- `--concurrency` limits how many tones can play at once.

Requires `numpy`, `scapy` and `pyaudio`.
