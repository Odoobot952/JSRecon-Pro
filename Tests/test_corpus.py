import unittest
from jsrecon_pro.corpus import iter_cases
class CorpusTests(unittest.TestCase):
    def test_count(self):
        self.assertEqual(len(list(iter_cases(20))), 20)
    def test_ids(self):
        self.assertEqual([x["id"] for x in iter_cases(3)], [1,2,3])
    def test_invalid(self):
        with self.assertRaises(ValueError): list(iter_cases(0))
if __name__ == "__main__": unittest.main()
