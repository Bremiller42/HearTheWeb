import numpy as np
import pyaudio
import atexit
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


# Frequencies for different results
tcp_upstream_freq = 330
tcp_downstream_freq = 523
udp_upstream_freq = 392
udp_downstream_freq = 261

local_network_prefix = "192.168."
futures = set()

# Maximum number of concurrent tones
max_concurrent_tones = 4
max_queue_size = 40

# PyAudio initialization
pa = pyaudio.PyAudio()
stream = pa.open(format=pyaudio.paInt16,
                channels=2,
                rate=44100,
                output=True,
                frames_per_buffer=512)

# Pre-generate tones
tone_cache = {}


def generate_tone(frequency, channel, duration=0.1, sample_rate=44100, volume=0.1, fade_duration=0.05):
    fade_duration = min(fade_duration, duration / 2)
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = np.sin(frequency * t * 2 * np.pi)

    # Fade out to reduce popping
    fade_out = np.linspace(1, 0, int(sample_rate * fade_duration), False)
    tone[-len(fade_out):] *= fade_out
    tone *= volume

    # Convert to 16-bit audio format
    audio = (tone * 32767 / np.max(np.abs(tone))).astype(np.int16)

    # Create stereo audio
    stereo_audio = np.zeros((len(audio), 2), dtype=np.int16)
    if channel == 'left':
        stereo_audio[:, 0] = audio
    else:  # 'right'
        stereo_audio[:, 1] = audio

    return stereo_audio.tobytes()


def preload_tones():
    for freq in [tcp_upstream_freq, tcp_downstream_freq, udp_upstream_freq, udp_downstream_freq]:
        for channel in ['left', 'right']:
            tone_cache[(freq, channel)] = generate_tone(freq, channel)


def play_tone(stream, frequency, channel):
    audio_data = tone_cache[(frequency, channel)]
    stream.write(audio_data)
    print(f"Playing {frequency} Hz on {channel} channel")


def tone_worker(stream, frequency, channel):
    play_tone(stream, frequency, channel)


def is_upstream(packet):
    return packet[IP].src.startswith(local_network_prefix)


def packet_callback(packet):
    global futures
    if IP in packet:
        tone_frequency = None
        channel = None
        if TCP in packet or UDP in packet:
            is_packet_upstream = is_upstream(packet)
            tone_frequency = tcp_upstream_freq if TCP in packet and is_packet_upstream else tcp_downstream_freq
            tone_frequency = udp_upstream_freq if UDP in packet and is_packet_upstream else udp_downstream_freq
            channel = 'left' if is_packet_upstream else 'right'

        if tone_frequency:
            futures = {f for f in futures if not f.done()}
            if len(futures) < max_queue_size:
                future = executor.submit(tone_worker, stream, tone_frequency, channel)
                futures.add(future)
            else:
                print("Queue is full, skipping tone.")


def cleanup_audio():
    stream.stop_stream()
    stream.close()
    pa.terminate()


if __name__ == "__main__":
    preload_tones()  # Preload tones into cache
    executor = ThreadPoolExecutor(max_workers=max_concurrent_tones)
    sniff(prn=packet_callback, store=False)
    atexit.register(cleanup_audio)
