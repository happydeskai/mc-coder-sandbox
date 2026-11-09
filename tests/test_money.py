"""Tests for tools.money.format_pence. Run from the repo root: python3 -m unittest discover -s tests -t ."""
import unittest

from tools.money import format_pence


class FormatPenceTest(unittest.TestCase):
    def test_example_from_ticket(self):
        self.assertEqual(format_pence(1234), "£12.34")

    def test_edge_cases(self):
        self.assertEqual(format_pence(0), "£0.00")
        self.assertEqual(format_pence(5), "£0.05")
        self.assertEqual(format_pence(99), "£0.99")
        self.assertEqual(format_pence(100), "£1.00")
        self.assertEqual(format_pence(10), "£0.10")

    def test_large_amount_has_no_thousands_separator(self):
        self.assertEqual(format_pence(123456789), "£1234567.89")

    def test_negative_amounts_put_the_minus_before_the_pound_sign(self):
        # Chosen convention: "-£12.34" (UK style for refunds and credits), never "£-12.34".
        self.assertEqual(format_pence(-1234), "-£12.34")
        self.assertEqual(format_pence(-5), "-£0.05")
        self.assertEqual(format_pence(-100), "-£1.00")

    def test_rejects_non_integer_pence(self):
        # Money is held as integer pence; a float or bool is a caller bug, not something to round silently.
        for bad in (12.34, 1234.0, "1234", None, True):
            with self.assertRaises(TypeError):
                format_pence(bad)


if __name__ == "__main__":
    unittest.main()
