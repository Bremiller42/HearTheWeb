"""Play short stereo tones for network packets."""

import argparse
import atexit
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pyaudio
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Default tone frequencies
tcp_upstream_freq = 330
tcp_downstream_freq = 523
udp_upstream_freq = 392
udp_downstream_freq = 261

# Default network prefix (can be overridden via CLI)
local_network_prefix = "192.168."

# Pre-generated tone cache and other globals
tone_cache = {}
futures = set()
stream = None
pa = None
max_concurrent_tones = 5
max_queue_size = 40

def generate_tone(frequency: int, channel: str, duration: float, sample_rate: int, volume: float) -> bytes:
    """Generate a stereo tone and return raw bytes."""
    fade_duration = min(0.05, duration / 2)
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = np.sin(frequency * t * 2 * np.pi)

    fade_out = np.linspace(1, 0, int(sample_rate * fade_duration), False)
    tone[-len(fade_out):] *= fade_out
    tone *= volume

    audio = (tone * 32767 / np.max(np.abs(tone))).astype(np.int16)

    stereo_audio = np.zeros((len(audio), 2), dtype=np.int16)
    if channel == "left":
        stereo_audio[:, 0] = audio
    else:
        stereo_audio[:, 1] = audio
    return stereo_audio.tobytes()


def preload_tones(duration: float, sample_rate: int, volume: float) -> None:
    """Pre-generate audio for all tone types."""
    for freq in [tcp_upstream_freq, tcp_downstream_freq, udp_upstream_freq, udp_downstream_freq]:
        for ch in ["left", "right"]:
            tone_cache[(freq, ch)] = generate_tone(freq, ch, duration, sample_rate, volume)


def play_tone(frequency: int, channel: str) -> None:
    """Play a pre-generated tone on the shared stream."""
    if (frequency, channel) not in tone_cache:
        return
    stream.write(tone_cache[(frequency, channel)])

def tone_worker(frequency: int, channel: str) -> None:
    play_tone(frequency, channel)

def is_upstream(packet: "Packet") -> bool:
    return packet[IP].src.startswith(local_network_prefix)


def packet_callback(packet) -> None:
    global futures
    if IP in packet:
        tone_frequency = None
        channel = None
        if TCP in packet:
            is_packet_upstream = is_upstream(packet)
            tone_frequency = tcp_upstream_freq if is_packet_upstream else tcp_downstream_freq
            channel = "left" if is_packet_upstream else "right"
        elif UDP in packet:
            is_packet_upstream = is_upstream(packet)
            tone_frequency = udp_upstream_freq if is_packet_upstream else udp_downstream_freq
            channel = "left" if is_packet_upstream else "right"

        if tone_frequency:
            # Check for room in queue, if not skip tone
            futures = {f for f in futures if not f.done()}  # Remove completed tasks
            if len(futures) < max_queue_size:
                future = executor.submit(tone_worker, tone_frequency, channel)
                futures.add(future)
            else:
                print("Queue is full, skipping tone.")

# Cleanup PyAudio
def cleanup_audio() -> None:
    if stream is not None:
        stream.stop_stream()
        stream.close()
    if pa is not None:
        pa.terminate()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hear network packets as tones")
    parser.add_argument("--prefix", default="192.168.", help="Local network prefix")
    parser.add_argument("--interface", "-i", help="Network interface to sniff")
    parser.add_argument("--volume", type=float, default=0.1, help="Playback volume")
    parser.add_argument("--sample-rate", type=int, default=44100, help="Sample rate")
    parser.add_argument("--duration", type=float, default=0.15, help="Tone duration")
    parser.add_argument("--concurrency", type=int, default=5, help="Maximum concurrent tones")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    local_network_prefix = args.prefix
    max_concurrent_tones = args.concurrency

    pa = pyaudio.PyAudio()
    stream = pa.open(
        format=pyaudio.paInt16,
        channels=2,
        rate=args.sample_rate,
        output=True,
        frames_per_buffer=512,
    )

    preload_tones(args.duration, args.sample_rate, args.volume)
    executor = ThreadPoolExecutor(max_workers=max_concurrent_tones)
    sniff(prn=packet_callback, store=False, iface=args.interface)
    atexit.register(cleanup_audio)
