#!/usr/bin/env python3
"""
Bible-based Brain Wallet Password Generator

This script generates variations of Bible phrases that people might use
as brain wallet passphrases. It applies common password transformation
patterns that users typically employ.

Transformation categories:
1. Case variations (lowercase, uppercase, title case, camelCase)
2. Space/separator variations (no space, underscore, hyphen, period)
3. Leetspeak substitutions (a→@/4, e→3, i→1, o→0, s→$, t→7)
4. Common prefixes/suffixes (numbers, special chars, religious words)
5. Word order variations (reverse, swap first/last)
6. Abbreviations (first letter of each word)
7. Biblical references (Genesis1:1, John3:16 style)
8. Punctuation removal/modification
9. Combinations of multiple phrases
"""

import re
import itertools
from typing import Set, List, Generator
from pathlib import Path

# Famous Bible verses with their references
FAMOUS_VERSES = {
    "Genesis 1:1": "In the beginning God created the heaven and the earth",
    "Genesis 1:3": "Let there be light",
    "John 3:16": "For God so loved the world that he gave his only begotten Son",
    "John 1:1": "In the beginning was the Word",
    "John 14:6": "I am the way the truth and the life",
    "John 8:32": "The truth shall set you free",
    "Psalm 23:1": "The Lord is my shepherd I shall not want",
    "Psalm 23:4": "Yea though I walk through the valley of the shadow of death",
    "Psalm 46:10": "Be still and know that I am God",
    "Psalm 119:105": "Thy word is a lamp unto my feet",
    "Matthew 6:9": "Our Father which art in heaven hallowed be thy name",
    "Matthew 7:7": "Ask and it shall be given you seek and ye shall find",
    "Matthew 5:5": "Blessed are the meek for they shall inherit the earth",
    "Matthew 5:9": "Blessed are the peacemakers",
    "Matthew 22:39": "Love thy neighbor as thyself",
    "Matthew 7:12": "Do unto others as you would have them do unto you",
    "Matthew 19:24": "It is easier for a camel to go through the eye of a needle",
    "Exodus 20:13": "Thou shalt not kill",
    "Exodus 20:15": "Thou shalt not steal",
    "Exodus 20:12": "Honor thy father and thy mother",
    "Exodus 3:14": "I am that I am",
    "Proverbs 3:5": "Trust in the Lord with all thine heart",
    "Proverbs 16:18": "Pride goeth before a fall",
    "Romans 8:28": "All things work together for good",
    "Philippians 4:13": "I can do all things through Christ",
    "Isaiah 40:31": "They that wait upon the Lord shall renew their strength",
    "Jeremiah 29:11": "For I know the plans I have for you",
    "1 Corinthians 13:13": "Faith hope and love",
    "Revelation 22:13": "I am Alpha and Omega the beginning and the end",
    "1 John 4:8": "God is love",
    "Hebrews 11:1": "Faith is the substance of things hoped for",
}

# Short memorable phrases from the Bible
SHORT_PHRASES = [
    "Let there be light",
    "God is love",
    "The Lord is my shepherd",
    "I shall not want",
    "The truth shall set you free",
    "Ask and it shall be given",
    "Seek and ye shall find",
    "Knock and it shall be opened",
    "Love thy neighbor",
    "Blessed are the meek",
    "Blessed are the peacemakers",
    "Faith can move mountains",
    "Eye for an eye",
    "Turn the other cheek",
    "Cast the first stone",
    "The good shepherd",
    "The prodigal son",
    "Loaves and fishes",
    "Water into wine",
    "Render unto Caesar",
    "Man shall not live by bread alone",
    "The love of money is the root of all evil",
    "Alpha and Omega",
    "The beginning and the end",
    "I am that I am",
    "Thou shalt not kill",
    "Thou shalt not steal",
    "Honor thy father and mother",
    "In the beginning",
    "In the beginning God created",
    "Heaven and earth",
    "The heavens and the earth",
    "Fear no evil",
    "I will fear no evil",
    "Thy rod and thy staff",
    "My cup runneth over",
    "He restoreth my soul",
    "Green pastures",
    "Still waters",
    "Goodness and mercy",
    "Ashes to ashes",
    "Dust to dust",
    "Forbidden fruit",
    "Garden of Eden",
    "Adam and Eve",
    "Cain and Abel",
    "Noah's Ark",
    "Tower of Babel",
    "Sodom and Gomorrah",
    "Burning bush",
    "Ten Commandments",
    "Promised Land",
    "David and Goliath",
    "Solomon's wisdom",
    "Daniel in the lion's den",
    "Jonah and the whale",
    "Baptism by fire",
    "Salt of the earth",
    "Light of the world",
    "Lamb of God",
    "Son of God",
    "Son of Man",
    "Holy Spirit",
    "Holy Ghost",
    "Kingdom of Heaven",
    "Kingdom of God",
    "Last Supper",
    "Bread of life",
    "Living water",
    "Good Samaritan",
    "Pearls before swine",
    "Wolf in sheep's clothing",
    "Den of thieves",
    "House of God",
    "Word of God",
    "Children of God",
    "Body of Christ",
    "Blood of Christ",
    "Cross of Christ",
    "Resurrection",
    "Salvation",
    "Redemption",
    "Eternal life",
    "Everlasting life",
    "Born again",
    "New testament",
    "Old testament",
    "Hallelujah",
    "Amen",
    "Hosanna",
    "Emmanuel",
    "Messiah",
    "Christ",
    "Jesus",
    "Jesus Christ",
    "Jesus saves",
    "Jesus is Lord",
    "Lord Jesus",
    "Lord Jesus Christ",
    "Glory to God",
    "Praise the Lord",
    "God bless",
    "God bless you",
    "God bless America",
    "In God we trust",
    "One nation under God",
    "So help me God",
]

# Biblical names that people might use
BIBLICAL_NAMES = [
    "Adam", "Eve", "Cain", "Abel", "Noah", "Abraham", "Isaac", "Jacob",
    "Joseph", "Moses", "Aaron", "David", "Solomon", "Elijah", "Isaiah",
    "Jeremiah", "Daniel", "Jonah", "Matthew", "Mark", "Luke", "John",
    "Peter", "Paul", "James", "Mary", "Martha", "Lazarus", "Thomas",
    "Judas", "Satan", "Lucifer", "Gabriel", "Michael", "Raphael",
    "Bethlehem", "Jerusalem", "Nazareth", "Galilee", "Jordan", "Sinai",
]

# Common password suffixes
COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "!!!", "@", "#", "$", "*",
    ".", "..", "...",
    "0", "00", "000",
    "1!", "123!", "1234!",
    "666", "777", "888", "999",
    "2000", "2001", "2008", "2009", "2010", "2011", "2012", 
    "2013", "2014", "2015", "2016", "2017", "2018", "2019",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "01", "07", "11", "13", "21", "33", "42", "69",
    "God", "god", "GOD",
    "Jesus", "jesus", "JESUS",
    "Christ", "christ", "CHRIST",
    "Amen", "amen", "AMEN",
    "btc", "BTC", "bitcoin", "Bitcoin", "BITCOIN",
    "crypto", "Crypto", "CRYPTO",
]

# Common password prefixes
COMMON_PREFIXES = [
    "", "The", "the", "THE",
    "my", "My", "MY",
    "i", "I",
    "God", "god", "GOD",
    "Jesus", "jesus", "JESUS",
    "Lord", "lord", "LORD",
    "1", "123",
    "@", "#", "$",
    "btc", "BTC",
]

# Leetspeak substitution mappings
LEET_BASIC = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
LEET_EXTENDED = {'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$', 't': '+'}

def apply_case_variations(text: str) -> Generator[str, None, None]:
    """Apply case variations to text."""
    yield text  # Original
    yield text.lower()  # lowercase
    yield text.upper()  # UPPERCASE
    yield text.title()  # Title Case
    yield text.capitalize()  # First letter only
    
    # camelCase (first word lowercase, rest title)
    words = text.split()
    if len(words) > 1:
        yield words[0].lower() + ''.join(w.capitalize() for w in words[1:])
        yield words[0].capitalize() + ''.join(w.lower() for w in words[1:])
    
    # Alternating case
    yield ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    yield ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(text))

def apply_separator_variations(text: str) -> Generator[str, None, None]:
    """Apply separator/space variations."""
    yield text  # Original with spaces
    yield text.replace(' ', '')  # NoSpaces
    yield text.replace(' ', '_')  # Under_Score
    yield text.replace(' ', '-')  # Hyphen-Ated
    yield text.replace(' ', '.')  # Dot.Separated
    yield text.replace(' ', ',')  # Comma,Separated
    yield text.replace(' ', '+')  # Plus+Separated

def apply_leetspeak(text: str) -> Generator[str, None, None]:
    """Apply leetspeak substitutions."""
    yield text  # Original
    
    # Basic leetspeak
    leet_text = text.lower()
    for orig, leet in LEET_BASIC.items():
        leet_text = leet_text.replace(orig, leet)
    yield leet_text
    
    # Extended leetspeak
    leet_text = text.lower()
    for orig, leet in LEET_EXTENDED.items():
        leet_text = leet_text.replace(orig, leet)
    yield leet_text
    
    # Partial leetspeak (only vowels)
    vowel_leet = {'a': '4', 'e': '3', 'i': '1', 'o': '0'}
    leet_text = text.lower()
    for orig, leet in vowel_leet.items():
        leet_text = leet_text.replace(orig, leet)
    yield leet_text

def apply_word_order_variations(text: str) -> Generator[str, None, None]:
    """Apply word order variations."""
    words = text.split()
    yield text  # Original
    
    if len(words) > 1:
        yield ' '.join(reversed(words))  # Reverse all words
        yield ' '.join([words[-1]] + words[1:-1] + [words[0]])  # Swap first and last
        yield ' '.join(words[1:] + [words[0]])  # Move first to end
        yield ' '.join([words[-1]] + words[:-1])  # Move last to start

def get_abbreviation(text: str) -> str:
    """Get first letter of each word."""
    words = text.split()
    return ''.join(w[0] if w else '' for w in words)

def remove_punctuation(text: str) -> str:
    """Remove all punctuation."""
    return re.sub(r'[^\w\s]', '', text)

def remove_vowels(text: str) -> str:
    """Remove vowels (consonants only)."""
    return re.sub(r'[aeiouAEIOU]', '', text)

def format_bible_reference(ref: str) -> Generator[str, None, None]:
    """Generate variations of a Bible reference."""
    # "Genesis 1:1" -> various formats
    yield ref  # Genesis 1:1
    yield ref.replace(' ', '')  # Genesis1:1
    yield ref.replace(':', '')  # Genesis 11
    yield ref.replace(' ', '').replace(':', '')  # Genesis11
    yield ref.lower()  # genesis 1:1
    yield ref.lower().replace(' ', '')  # genesis1:1
    yield ref.upper()  # GENESIS 1:1
    yield ref.upper().replace(' ', '')  # GENESIS1:1
    
    # Just the numbers
    match = re.search(r'(\d+):(\d+)', ref)
    if match:
        yield f"{match.group(1)}:{match.group(2)}"  # 1:1
        yield f"{match.group(1)}{match.group(2)}"  # 11

def generate_combined_phrases(phrases: List[str], max_combos: int = 10000) -> Generator[str, None, None]:
    """Generate combinations of short phrases."""
    short_phrases = [p for p in phrases if len(p.split()) <= 4][:50]  # Limit to prevent explosion
    count = 0
    
    for p1, p2 in itertools.combinations(short_phrases, 2):
        if count >= max_combos:
            break
        yield f"{p1} {p2}"
        yield f"{p1}{p2}"
        yield f"{p1}_{p2}"
        count += 3

def generate_all_variations(phrase: str, include_extended: bool = True) -> Set[str]:
    """Generate all variations of a phrase."""
    variations = set()
    
    # Base phrase
    variations.add(phrase)
    
    # Cleaned version (remove punctuation)
    cleaned = remove_punctuation(phrase)
    variations.add(cleaned)
    
    # Apply case variations
    for text in [phrase, cleaned]:
        for case_var in apply_case_variations(text):
            variations.add(case_var)
            
            # Apply separator variations
            for sep_var in apply_separator_variations(case_var):
                variations.add(sep_var)
                
                # Apply prefixes/suffixes (limited)
                if include_extended:
                    for suffix in COMMON_SUFFIXES[:30]:  # Limit suffixes
                        variations.add(f"{sep_var}{suffix}")
                    for prefix in COMMON_PREFIXES[:15]:  # Limit prefixes
                        variations.add(f"{prefix}{sep_var}")
    
    # Leetspeak variations (only for cleaned versions without spaces)
    for leet_var in apply_leetspeak(cleaned.replace(' ', '')):
        variations.add(leet_var)
        if include_extended:
            for suffix in COMMON_SUFFIXES[:10]:
                variations.add(f"{leet_var}{suffix}")
    
    # Word order variations
    for order_var in apply_word_order_variations(cleaned):
        variations.add(order_var)
        variations.add(order_var.lower())
        variations.add(order_var.replace(' ', ''))
    
    # Abbreviation
    abbrev = get_abbreviation(cleaned)
    if len(abbrev) >= 3:
        variations.add(abbrev)
        variations.add(abbrev.lower())
        variations.add(abbrev.upper())
        if include_extended:
            for suffix in COMMON_SUFFIXES[:10]:
                variations.add(f"{abbrev}{suffix}")
    
    # Remove vowels
    no_vowels = remove_vowels(cleaned).replace(' ', '')
    if len(no_vowels) >= 3:
        variations.add(no_vowels)
        variations.add(no_vowels.lower())
        variations.add(no_vowels.upper())
    
    return variations

def generate_verse_with_reference(ref: str, verse: str) -> Set[str]:
    """Generate variations that combine reference with verse."""
    variations = set()
    
    # Reference variations
    for ref_var in format_bible_reference(ref):
        variations.add(ref_var)
        
        # Reference + verse combinations
        variations.add(f"{ref_var} {verse}")
        variations.add(f"{ref_var}:{verse}")
        variations.add(f"{ref_var}-{verse}")
        variations.add(f"{verse} {ref_var}")
        variations.add(f"{verse}({ref_var})")
        
        # Short combinations
        words = verse.split()[:3]
        short_verse = ' '.join(words)
        variations.add(f"{ref_var} {short_verse}")
        variations.add(f"{ref_var}{short_verse.replace(' ', '')}")
    
    return variations

def main():
    """Main function to generate the password list."""
    output_dir = Path(__file__).parent.parent / "wordlists"
    output_file = output_dir / "bible_brainwallet.txt"
    
    all_passwords: Set[str] = set()
    
    print("=" * 60)
    print("Bible Brain Wallet Password Generator")
    print("=" * 60)
    
    # 1. Process famous verses with references
    print("\n[1/6] Processing famous verses with references...")
    for ref, verse in FAMOUS_VERSES.items():
        # Verse variations
        all_passwords.update(generate_all_variations(verse, include_extended=True))
        # Reference + verse combinations
        all_passwords.update(generate_verse_with_reference(ref, verse))
    print(f"      Current total: {len(all_passwords):,}")
    
    # 2. Process short phrases
    print("\n[2/6] Processing short memorable phrases...")
    for phrase in SHORT_PHRASES:
        all_passwords.update(generate_all_variations(phrase, include_extended=True))
    print(f"      Current total: {len(all_passwords):,}")
    
    # 3. Biblical names with variations
    print("\n[3/6] Processing Biblical names...")
    for name in BIBLICAL_NAMES:
        all_passwords.add(name)
        all_passwords.add(name.lower())
        all_passwords.add(name.upper())
        for suffix in COMMON_SUFFIXES[:20]:
            all_passwords.add(f"{name}{suffix}")
            all_passwords.add(f"{name.lower()}{suffix}")
        for prefix in COMMON_PREFIXES[:10]:
            all_passwords.add(f"{prefix}{name}")
    print(f"      Current total: {len(all_passwords):,}")
    
    # 4. Common phrase combinations
    print("\n[4/6] Generating phrase combinations...")
    for combo in generate_combined_phrases(SHORT_PHRASES, max_combos=5000):
        all_passwords.add(combo)
        all_passwords.add(combo.lower())
        all_passwords.add(combo.replace(' ', ''))
    print(f"      Current total: {len(all_passwords):,}")
    
    # 5. Special patterns people might use
    print("\n[5/6] Adding special patterns...")
    special_patterns = [
        # Common brain wallet attempts
        "satoshi", "Satoshi", "SATOSHI",
        "satoshi nakamoto", "Satoshi Nakamoto", "SATOSHI NAKAMOTO",
        "bitcoin", "Bitcoin", "BITCOIN",
        "nakamoto", "Nakamoto", "NAKAMOTO",
        
        # Bible + Bitcoin combinations
        "BibleBTC", "bibleBTC", "BIBLEBTC",
        "GodBTC", "godBTC", "GODBTC",
        "JesusBTC", "jesusBTC", "JESUSBTC",
        "ChristBTC", "christBTC", "CHRISTBTC",
        
        # Number patterns
        "777", "666", "888", "333", "144000",
        "7777777", "6666666", "8888888",
        "12", "12apostles", "12disciples",
        "10commandments", "10Commandments",
        "40days", "40nights", "40years",
        "3days", "7days", "7seals", "7trumpets",
        
        # Common religious passwords
        "password", "Password", "PASSWORD",
        "letmein", "LetMeIn", "LETMEIN",
        "trustinGod", "TrustInGod", "TRUSTINGOD",
        "faithinhim", "FaithInHim", "FAITHINHIM",
        "godisgood", "GodIsGood", "GODISGOOD",
        "godislove", "GodIsLove", "GODISLOVE",
        "jesussaves", "JesusSaves", "JESUSSAVES",
        "praisejesus", "PraiseJesus", "PRAISEJESUS",
        "praisethelord", "PraiseTheLord", "PRAISETHELORD",
        "godbless", "GodBless", "GODBLESS",
        "blessed", "Blessed", "BLESSED",
        "holy", "Holy", "HOLY",
        "sacred", "Sacred", "SACRED",
        "divine", "Divine", "DIVINE",
        "faith", "Faith", "FAITH",
        "hope", "Hope", "HOPE",
        "love", "Love", "LOVE",
        "grace", "Grace", "GRACE",
        "mercy", "Mercy", "MERCY",
        "glory", "Glory", "GLORY",
        "hallelujah", "Hallelujah", "HALLELUJAH",
        "hosanna", "Hosanna", "HOSANNA",
        "emmanuel", "Emmanuel", "EMMANUEL",
        "immanuel", "Immanuel", "IMMANUEL",
        
        # Hebrew/Greek words
        "YHWH", "Yahweh", "yahweh",
        "Elohim", "elohim", "ELOHIM",
        "Adonai", "adonai", "ADONAI",
        "Shalom", "shalom", "SHALOM",
        "Maranatha", "maranatha", "MARANATHA",
        "Agape", "agape", "AGAPE",
        "Logos", "logos", "LOGOS",
        "Christos", "christos", "CHRISTOS",
        "Theos", "theos", "THEOS",
        "Pneuma", "pneuma", "PNEUMA",
        "Abba", "abba", "ABBA",
        "Selah", "selah", "SELAH",
    ]
    
    for pattern in special_patterns:
        all_passwords.add(pattern)
        for suffix in COMMON_SUFFIXES[:15]:
            all_passwords.add(f"{pattern}{suffix}")
    print(f"      Current total: {len(all_passwords):,}")
    
    # 6. Read existing bible_sample.txt and add variations
    print("\n[6/6] Processing existing bible_sample.txt...")
    sample_file = output_dir / "bible_sample.txt"
    if sample_file.exists():
        with open(sample_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    all_passwords.update(generate_all_variations(line, include_extended=True))
    print(f"      Current total: {len(all_passwords):,}")
    
    # Filter out empty and too short passwords
    all_passwords = {p for p in all_passwords if p and len(p) >= 1}
    
    # Sort for consistency and write to file
    print(f"\n[FINAL] Writing {len(all_passwords):,} passwords to {output_file}")
    
    sorted_passwords = sorted(all_passwords, key=lambda x: (len(x), x))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for password in sorted_passwords:
            f.write(f"{password}\n")
    
    print(f"\nDone! Generated {len(all_passwords):,} unique password variations.")
    print(f"Output file: {output_file}")
    print("\nStatistics:")
    print(f"  - Shortest password: {min(len(p) for p in all_passwords)} characters")
    print(f"  - Longest password: {max(len(p) for p in all_passwords)} characters")
    print(f"  - Average length: {sum(len(p) for p in all_passwords) / len(all_passwords):.1f} characters")

if __name__ == "__main__":
    main()

