import unittest
from main import generate_tone

class ToneGenerationTest(unittest.TestCase):
    def test_generate_bytes(self):
        data = generate_tone(440, 'left', duration=0.1, sample_rate=44100, volume=0.1)
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

if __name__ == '__main__':
    unittest.main()
