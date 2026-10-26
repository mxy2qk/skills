# English Word Frequency Data

`english_10k.txt` is a frequency-ordered list of the 10,000 most common
English words, used by `ctfkit.util.word_score` / `substitution_score` to
score classical-cipher candidates.

Source: the `google-10000-english` list, derived from the Google Web Trillion
Word Corpus:
https://github.com/first20hours/google-10000-english

The file is normalized to one lowercase alphabetic word per line and is used
only as a statistical scoring table. If the file is missing, the toolkit falls
back to the smaller embedded `COMMON_WORDS` table and still works.
