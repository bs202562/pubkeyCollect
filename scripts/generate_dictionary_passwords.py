#!/usr/bin/env python3
"""
Dictionary-based Brain Wallet Password Generator

This script generates password variations based on common English words
and patterns that people typically use as brain wallet passphrases.

Includes:
1. Common English words (top frequency)
2. Word combinations (2-4 words)
3. Common password patterns
4. Leetspeak variations
5. Number/symbol suffixes
6. Keyboard patterns
7. Popular phrases
"""

import itertools
from typing import Set, List, Generator
from pathlib import Path

# Top 500 most common English words used in passwords
COMMON_WORDS = [
    # Basic words
    "password", "love", "life", "money", "happy", "dream", "hope", "faith",
    "trust", "peace", "truth", "power", "magic", "secret", "dragon", "master",
    "shadow", "light", "dark", "night", "star", "moon", "sun", "fire", "water",
    "earth", "wind", "rock", "gold", "silver", "diamond", "crystal", "angel",
    "devil", "demon", "ghost", "spirit", "soul", "heart", "mind", "body",
    
    # Animals
    "dog", "cat", "bird", "fish", "wolf", "bear", "lion", "tiger", "eagle",
    "shark", "snake", "horse", "monkey", "rabbit", "fox", "deer", "dragon",
    "phoenix", "unicorn", "panda", "dolphin", "butterfly", "spider", "bee",
    
    # Colors
    "red", "blue", "green", "yellow", "black", "white", "orange", "purple",
    "pink", "brown", "gray", "silver", "gold", "rainbow",
    
    # Numbers as words
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "hundred", "thousand", "million", "billion", "zero", "first",
    
    # Tech/Internet
    "admin", "user", "root", "guest", "test", "demo", "login", "access",
    "system", "server", "network", "internet", "computer", "digital", "cyber",
    "hacker", "coder", "programmer", "developer", "geek", "nerd", "tech",
    "bitcoin", "crypto", "blockchain", "satoshi", "nakamoto", "btc", "eth",
    
    # Gaming
    "game", "gamer", "player", "winner", "loser", "champion", "hero", "warrior",
    "knight", "ninja", "samurai", "pirate", "viking", "soldier", "assassin",
    "killer", "sniper", "hunter", "fighter", "boss", "king", "queen", "prince",
    "princess", "lord", "lady", "wizard", "witch", "mage", "sorcerer",
    
    # Music/Entertainment
    "music", "rock", "jazz", "blues", "metal", "punk", "dance", "party",
    "movie", "star", "fame", "celebrity", "band", "guitar", "piano", "drum",
    
    # Sports
    "soccer", "football", "basketball", "baseball", "tennis", "golf", "hockey",
    "boxing", "racing", "running", "swimming", "skiing", "surfing", "sport",
    "team", "player", "coach", "champion", "winner", "goal", "score",
    
    # Nature
    "nature", "forest", "mountain", "ocean", "river", "lake", "beach", "island",
    "desert", "jungle", "garden", "flower", "tree", "leaf", "grass", "sky",
    "cloud", "rain", "snow", "storm", "thunder", "lightning", "sunset", "sunrise",
    
    # Family
    "family", "mother", "father", "sister", "brother", "baby", "child", "kids",
    "son", "daughter", "mom", "dad", "mama", "papa", "grandma", "grandpa",
    "wife", "husband", "friend", "buddy", "mate", "partner", "lover",
    
    # Time
    "time", "day", "night", "morning", "evening", "today", "tomorrow", "forever",
    "always", "never", "now", "past", "future", "year", "month", "week",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "spring", "summer", "autumn",
    "fall", "winter", "christmas", "halloween", "easter", "birthday",
    
    # Emotions
    "love", "hate", "happy", "sad", "angry", "fear", "joy", "hope", "dream",
    "wish", "desire", "passion", "emotion", "feeling", "smile", "laugh", "cry",
    
    # Actions
    "run", "walk", "jump", "fly", "swim", "dance", "sing", "play", "fight",
    "kill", "live", "die", "love", "hate", "think", "know", "believe", "trust",
    "create", "destroy", "build", "break", "open", "close", "start", "stop",
    
    # Adjectives
    "big", "small", "great", "super", "mega", "ultra", "extreme", "ultimate",
    "cool", "hot", "cold", "fast", "slow", "strong", "weak", "smart", "crazy",
    "wild", "free", "true", "real", "fake", "good", "bad", "best", "worst",
    "new", "old", "young", "ancient", "modern", "classic", "simple", "complex",
    
    # Common names
    "john", "james", "michael", "david", "robert", "william", "richard", "joseph",
    "thomas", "charles", "daniel", "matthew", "andrew", "joshua", "anthony",
    "mary", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica",
    "sarah", "karen", "nancy", "lisa", "betty", "margaret", "sandra", "ashley",
    "alex", "sam", "max", "jack", "jake", "mike", "chris", "nick", "tom", "bob",
    
    # Places
    "america", "usa", "england", "london", "paris", "tokyo", "china", "russia",
    "germany", "france", "italy", "spain", "brazil", "canada", "australia",
    "california", "texas", "florida", "newyork", "losangeles", "chicago",
    
    # Objects
    "car", "house", "home", "door", "window", "key", "lock", "phone", "computer",
    "camera", "book", "money", "coin", "card", "ring", "watch", "gun", "sword",
    "knife", "hammer", "tool", "machine", "robot", "rocket", "plane", "ship",
    
    # Abstract
    "idea", "thought", "mind", "brain", "memory", "dream", "vision", "goal",
    "plan", "strategy", "success", "failure", "victory", "defeat", "war", "peace",
    "freedom", "justice", "truth", "lie", "secret", "mystery", "magic", "power",
]

# Common password phrases and patterns
COMMON_PASSWORDS = [
    # Top passwords
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
    "michael", "football", "password1", "password123", "batman", "login",
    
    # Love patterns
    "iloveyou", "iloveu", "loveyou", "loveu", "mylove", "truelove", "lovelife",
    "lovelove", "love4ever", "love4u", "loveme", "iloveme",
    
    # Common phrases
    "letmein", "openup", "welcome", "hello", "goodbye", "thankyou", "please",
    "sorry", "helpme", "saveme", "trustme", "believeme", "followme",
    
    # Keyboard patterns
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "qweasd", "qweasdzxc", "1qaz2wsx", "1q2w3e4r", "1q2w3e", "zaq12wsx",
    "qazwsx", "qazwsxedc", "123qwe", "qwe123", "abc123", "123abc",
    
    # Number patterns
    "000000", "111111", "222222", "333333", "444444", "555555", "666666",
    "777777", "888888", "999999", "121212", "123123", "101010", "112233",
    "123321", "111222", "123654", "147258", "159357", "987654", "654321",
    
    # Year patterns
    "1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
    "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009",
    "2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019",
    "2020", "2021", "2022", "2023", "2024", "2025",
    
    # Crypto/Bitcoin related
    "bitcoin", "btc", "satoshi", "nakamoto", "satoshinakamoto", "blockchain",
    "crypto", "cryptocurrency", "ethereum", "eth", "litecoin", "ltc", "dogecoin",
    "hodl", "tothemoon", "moon", "lambo", "whenlambo", "diamond", "hands",
    "diamondhands", "paperhandsapestrong", "apestrong", "together",
    
    # Hacker/Security
    "hacker", "h4ck3r", "admin", "root", "sudo", "shell", "backdoor", "exploit",
    "virus", "malware", "trojan", "firewall", "secure", "security", "private",
    "anonymous", "anon", "darkweb", "deepweb", "tor", "vpn", "proxy",
    
    # Memes/Internet culture  
    "doge", "pepe", "meme", "lol", "lmao", "rofl", "yolo", "swag", "noob", "pwned",
    "owned", "epic", "fail", "win", "boss", "legend", "goat", "based", "cringe",
    
    # Expletives (common in passwords)
    "fuck", "shit", "damn", "hell", "ass", "bitch", "bastard",
    "fuckyou", "fuckoff", "fuckme", "bullshit", "asshole",
]

# Suffixes
COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "!!!", "@", "#", "$", "*", ".",
    "0", "00", "000", "01", "02", "07", "11", "13", "21", "69", "99",
    "1!", "123!", "1234!", "!@#", "!@#$",
    "666", "777", "888", "999",
    "2020", "2021", "2022", "2023", "2024", "2025",
]

# Prefixes
COMMON_PREFIXES = [
    "", "my", "My", "MY", "the", "The", "THE",
    "i", "I", "a", "A", "x", "X", "mr", "Mr", "MR",
    "super", "Super", "SUPER", "mega", "Mega", "MEGA",
    "1", "123", "@", "#",
]

# Leetspeak mappings
LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7', '+'],
    'g': ['9'],
    'b': ['8'],
    'l': ['1'],
}

def apply_case_variations(text: str) -> Generator[str, None, None]:
    """Apply case variations."""
    yield text
    yield text.lower()
    yield text.upper()
    yield text.capitalize()
    yield text.title()
    
    # camelCase
    words = text.split()
    if len(words) > 1:
        yield words[0].lower() + ''.join(w.capitalize() for w in words[1:])

def apply_leetspeak(text: str) -> Generator[str, None, None]:
    """Apply leetspeak substitutions."""
    yield text
    
    # Simple leetspeak (all substitutions)
    leet = text.lower()
    for char, replacements in LEET_MAP.items():
        leet = leet.replace(char, replacements[0])
    yield leet
    
    # Alternate leetspeak
    leet2 = text.lower()
    for char, replacements in LEET_MAP.items():
        if len(replacements) > 1:
            leet2 = leet2.replace(char, replacements[1])
        else:
            leet2 = leet2.replace(char, replacements[0])
    if leet2 != leet:
        yield leet2

def apply_separators(text: str) -> Generator[str, None, None]:
    """Apply separator variations for multi-word text."""
    yield text
    if ' ' in text:
        yield text.replace(' ', '')
        yield text.replace(' ', '_')
        yield text.replace(' ', '-')
        yield text.replace(' ', '.')

def generate_word_combinations(words: List[str], max_words: int = 3, max_combos: int = 50000) -> Generator[str, None, None]:
    """Generate word combinations."""
    count = 0
    
    # Single words
    for word in words:
        if count >= max_combos:
            return
        yield word
        count += 1
    
    # Two-word combinations (limited)
    if max_words >= 2:
        # Most common words for combinations
        combo_words = words[:100]
        for w1, w2 in itertools.product(combo_words, repeat=2):
            if w1 != w2:
                if count >= max_combos:
                    return
                yield f"{w1}{w2}"
                yield f"{w1} {w2}"
                yield f"{w1}_{w2}"
                count += 3
    
    # Three-word combinations (very limited)
    if max_words >= 3:
        top_words = words[:30]
        for w1, w2, w3 in itertools.permutations(top_words, 3):
            if count >= max_combos:
                return
            yield f"{w1}{w2}{w3}"
            count += 1

def generate_variations(text: str, include_extended: bool = True) -> Set[str]:
    """Generate all variations of a text."""
    variations = set()
    variations.add(text)
    
    # Case variations
    for case_var in apply_case_variations(text):
        variations.add(case_var)
        
        # Separator variations
        for sep_var in apply_separators(case_var):
            variations.add(sep_var)
            
            # Suffixes (limited)
            if include_extended:
                for suffix in COMMON_SUFFIXES[:25]:
                    variations.add(f"{sep_var}{suffix}")
                    
                # Prefixes (limited)
                for prefix in COMMON_PREFIXES[:10]:
                    variations.add(f"{prefix}{sep_var}")
    
    # Leetspeak
    no_space = text.replace(' ', '')
    for leet in apply_leetspeak(no_space):
        variations.add(leet)
        variations.add(leet.upper())
        if include_extended:
            for suffix in COMMON_SUFFIXES[:10]:
                variations.add(f"{leet}{suffix}")
    
    return variations

def generate_name_patterns(names: List[str]) -> Generator[str, None, None]:
    """Generate common name-based password patterns."""
    for name in names:
        yield name
        yield name.lower()
        yield name.upper()
        yield name.capitalize()
        
        # Name + numbers
        for num in ["1", "12", "123", "1234", "69", "99", "00", "01", "007"]:
            yield f"{name}{num}"
            yield f"{name.lower()}{num}"
            yield f"{name.capitalize()}{num}"
        
        # Name + year
        for year in ["1990", "1995", "2000", "2010", "2020", "2024"]:
            yield f"{name}{year}"
            yield f"{name.lower()}{year}"
        
        # Name + symbols
        for sym in ["!", "@", "#", "$", "*"]:
            yield f"{name}{sym}"
            yield f"{name.lower()}{sym}"
            yield f"{sym}{name}"

def generate_date_patterns() -> Generator[str, None, None]:
    """Generate date-based password patterns."""
    # Common date formats
    for month in range(1, 13):
        for day in [1, 10, 15, 20, 25, 28, 30, 31]:
            if day <= 28 or (day == 30 and month not in [2]) or (day == 31 and month in [1,3,5,7,8,10,12]):
                # MMDD
                yield f"{month:02d}{day:02d}"
                # DDMM
                yield f"{day:02d}{month:02d}"
    
    # Birthday patterns
    for year in range(1980, 2010):
        for month in [1, 6, 12]:
            for day in [1, 15]:
                yield f"{month:02d}{day:02d}{year}"
                yield f"{day:02d}{month:02d}{year}"
                yield f"{year}{month:02d}{day:02d}"
                yield f"{month:02d}{day:02d}{year % 100:02d}"

def generate_keyboard_patterns() -> Generator[str, None, None]:
    """Generate keyboard-based patterns."""
    patterns = [
        # Row patterns
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
        "qwert", "asdf", "zxcv", "poiuy", "lkjhg", "mnbvc",
        
        # Diagonal patterns
        "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
        "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn", "yhnujm",
        "qazwsxedc", "wsxedcrfv", "edcrfvtgb",
        "1qaz", "2wsx", "3edc", "1qaz2wsx", "1qaz2wsx3edc",
        
        # Number row patterns
        "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
        "321", "4321", "54321", "654321", "7654321", "87654321", "987654321",
        "147", "258", "369", "147258", "258369", "147258369",
        "159", "357", "159357", "135", "246", "135246",
        
        # Mixed patterns
        "1q2w3e", "1q2w3e4r", "1q2w3e4r5t",
        "q1w2e3", "q1w2e3r4", "q1w2e3r4t5",
        "1qaz2wsx", "2wsx3edc", "1qaz2wsx3edc",
        "qwe123", "123qwe", "asd123", "123asd", "zxc123", "123zxc",
        
        # Symbol patterns
        "!@#$", "!@#$%", "!@#$%^", "!@#$%^&", "!@#$%^&*",
        "qwerty!", "qwerty!@#", "123456!", "123456!@#",
    ]
    
    for p in patterns:
        yield p
        yield p.upper()

def main():
    """Main function."""
    output_dir = Path(__file__).parent.parent / "wordlists"
    output_file = output_dir / "dictionary_passwords.txt"
    
    all_passwords: Set[str] = set()
    
    print("=" * 60)
    print("Dictionary Password Generator")
    print("=" * 60)
    
    # 1. Common passwords
    print("\n[1/7] Processing common passwords...")
    for pwd in COMMON_PASSWORDS:
        all_passwords.update(generate_variations(pwd, include_extended=True))
    print(f"      Current total: {len(all_passwords):,}")
    
    # 2. Common words with variations
    print("\n[2/7] Processing common words...")
    for word in COMMON_WORDS:
        all_passwords.update(generate_variations(word, include_extended=True))
    print(f"      Current total: {len(all_passwords):,}")
    
    # 3. Word combinations
    print("\n[3/7] Generating word combinations...")
    for combo in generate_word_combinations(COMMON_WORDS[:150], max_words=2, max_combos=30000):
        all_passwords.add(combo)
        all_passwords.add(combo.lower())
        all_passwords.add(combo.upper())
        all_passwords.add(combo.capitalize())
        # Add common suffixes to combinations
        for suffix in COMMON_SUFFIXES[:10]:
            all_passwords.add(f"{combo}{suffix}")
    print(f"      Current total: {len(all_passwords):,}")
    
    # 4. Name patterns
    print("\n[4/7] Generating name patterns...")
    names = [w for w in COMMON_WORDS if w in [
        "john", "james", "michael", "david", "robert", "william", "richard",
        "joseph", "thomas", "charles", "daniel", "matthew", "andrew", "joshua",
        "mary", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica",
        "sarah", "alex", "sam", "max", "jack", "jake", "mike", "chris", "nick"
    ]]
    for pwd in generate_name_patterns(names):
        all_passwords.add(pwd)
    print(f"      Current total: {len(all_passwords):,}")
    
    # 5. Date patterns
    print("\n[5/7] Generating date patterns...")
    for pwd in generate_date_patterns():
        all_passwords.add(pwd)
    print(f"      Current total: {len(all_passwords):,}")
    
    # 6. Keyboard patterns
    print("\n[6/7] Generating keyboard patterns...")
    for pwd in generate_keyboard_patterns():
        all_passwords.add(pwd)
        for suffix in COMMON_SUFFIXES[:10]:
            all_passwords.add(f"{pwd}{suffix}")
    print(f"      Current total: {len(all_passwords):,}")
    
    # 7. Special patterns and phrases
    print("\n[7/7] Adding special patterns...")
    special_patterns = [
        # Common phrases
        "letmein", "openup", "welcome", "hello", "goodbye", "password",
        "opensesame", "abracadabra", "helloworld", "goodbye", "seeyou",
        
        # Action phrases
        "iloveyou", "ihateyou", "trustme", "believeme", "helpme", "saveme",
        "killme", "loveme", "hateme", "remember", "forgetme", "followme",
        "pleaseletmein", "justletmein", "openthedoor", "letmeinnow",
        
        # Motivational
        "nevergiveup", "justdoit", "yesican", "icanwin", "winning",
        "success", "failure", "impossible", "possible", "believe",
        "dreamsbig", "thinkbig", "workhard", "playhard", "stayhungry",
        "stayhumble", "keepgoing", "movingforward", "noexcuses",
        
        # Internet/Meme
        "420blaze", "420blazeit", "69nice", "noice", "stonks",
        "pepelaugh", "feelsgood", "feelsbad", "sadge", "poggers", "pogchamp",
        
        # Security related
        "changemelater", "temporarypassword", "defaultpassword", "testpassword",
        "adminadmin", "rootroot", "useruser", "guestguest", "testtest",
        "passw0rd", "p@ssw0rd", "p@ssword", "pa$$word", "p455w0rd",
        
        # Bitcoin/Crypto specific
        "hodlgang", "buythedip", "sellhigh", "buylow", "tothesky",
        "moonshot", "rocketship", "lamborghini", "wenlambo", "diamondhand",
        "paperhand", "cryptoking", "cryptoqueen", "bitcoinbillionaire",
        "satoshivision", "whitepaper", "genesis", "genesisblock",
    ]
    
    for pattern in special_patterns:
        all_passwords.update(generate_variations(pattern, include_extended=True))
    print(f"      Current total: {len(all_passwords):,}")
    
    # Filter out empty passwords
    all_passwords = {p for p in all_passwords if p and len(p) >= 1}
    
    # Sort and write
    print(f"\n[FINAL] Writing {len(all_passwords):,} passwords to {output_file}")
    
    sorted_passwords = sorted(all_passwords, key=lambda x: (len(x), x))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for pwd in sorted_passwords:
            f.write(f"{pwd}\n")
    
    print(f"\nDone! Generated {len(all_passwords):,} unique password variations.")
    print(f"Output file: {output_file}")
    print("\nStatistics:")
    print(f"  - Shortest password: {min(len(p) for p in all_passwords)} characters")
    print(f"  - Longest password: {max(len(p) for p in all_passwords)} characters")
    print(f"  - Average length: {sum(len(p) for p in all_passwords) / len(all_passwords):.1f} characters")

if __name__ == "__main__":
    main()

