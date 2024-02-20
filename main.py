import numpy as np
import pyaudio
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import atexit

# Frequencies for different results
tcp_upstream_freq = 330
tcp_downstream_freq = 523
udp_upstream_freq = 392
udp_downstream_freq = 261

local_network_prefix = "192.168."

# Maximum number of concurrent tones
max_concurrent_tones = 5
max_queue_size = 40

# PyAudio initialization
p = pyaudio.PyAudio()
futures = set()

def play_tone(frequency, channel, duration=0.15, sample_rate=44100, volume=0.1, fade_duration=0.05):
    fade_duration = min(fade_duration, duration / 2)
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = np.sin(frequency * t * 2 * np.pi)

    # Fade in and fade out to reduce popping
    fade_in = np.linspace(0, 1, int(sample_rate * fade_duration), False)
    fade_out = np.linspace(1, 0, int(sample_rate * fade_duration), False)
    tone[:len(fade_in)] *= fade_in
    tone[-len(fade_out):] *= fade_out

    tone *= volume

    # Convert to 16-bit audio format
    audio = (tone * 32767 / np.max(np.abs(tone))).astype(np.int16)

    # Create stereo audio by duplicating the tone and muting one channel
    if channel == 'left':
        stereo_audio = np.zeros((len(audio), 2), dtype=np.int16)
        stereo_audio[:, 0] = audio  # Left channel
    else:  # 'right'
        stereo_audio = np.zeros((len(audio), 2), dtype=np.int16)
        stereo_audio[:, 1] = audio  # Right channel

    # Open stream for stereo playback
    stream = p.open(format=pyaudio.paInt16,
                    channels=2,
                    rate=sample_rate,
                    output=True,
                    frames_per_buffer=512)

    # Play audio
    print(f"Playing {frequency} Hz on {channel} channel")
    stream.write(stereo_audio.tobytes())
    stream.stop_stream()
    stream.close()

def tone_worker(frequency, channel):
    play_tone(frequency, channel)

def is_upstream(packet):
    return packet[IP].src.startswith(local_network_prefix)

def packet_callback(packet):
    global futures
    if IP in packet:
        tone_frequency = None
        channel = None
        if TCP in packet:
            is_packet_upstream = is_upstream(packet)
            tone_frequency = tcp_upstream_freq if is_packet_upstream else tcp_downstream_freq
            channel = 'left' if is_packet_upstream else 'right'
        elif UDP in packet:
            is_packet_upstream = is_upstream(packet)
            tone_frequency = udp_upstream_freq if is_packet_upstream else udp_downstream_freq
            channel = 'left' if is_packet_upstream else 'right'

        if tone_frequency:
            # Check for room in queue, if not skip tone
            futures = {f for f in futures if not f.done()}  # Remove completed tasks
            if len(futures) < max_queue_size:
                future = executor.submit(tone_worker, tone_frequency, channel)
                futures.add(future)
            else:
                print("Queue is full, skipping tone.")

# Cleanup PyAudio
def cleanup_audio():
    p.terminate()

if (__name__ == "__main__"):
    executor = ThreadPoolExecutor(max_workers=max_concurrent_tones)
    sniff(prn=packet_callback, store=False)
    atexit.register(cleanup_audio)
