import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("pii_gateway.pii_engine")

# 1. Programmatic spaCy Model Check and Automatic Download
try:
    import spacy
    if not spacy.util.is_package("en_core_web_sm"):
        logger.info("spaCy model 'en_core_web_sm' not found. Programmatically downloading...")
        import spacy.cli
        spacy.cli.download("en_core_web_sm")
except Exception as e:
    logger.warning(f"Failed to check/download spaCy model en_core_web_sm: {e}")

# 2. Try to initialize Microsoft Presidio Analyzer Engine
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    
    # Configure Presidio to load en_core_web_sm explicitly
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    presidio_available = True
    logger.info("Microsoft Presidio Analyzer successfully initialized with en_core_web_sm.")
except Exception as e:
    logger.warning(
        f"Microsoft Presidio or spaCy model initialization failed: {e}. "
        "Falling back to custom Regex-only mode."
    )
    presidio_available = False
    analyzer = None

# Strict isolated regex patterns
REGEX_PATTERNS = {
    "EMAIL": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    # Strict 10-digit phone regex checking standard US area code and exchange formats
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IP": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "API_KEY": re.compile(r"\b(?:sk-[a-zA-Z0-9]{48}|AIzaSy[a-zA-Z0-9-_]{33}|[a-f0-9]{32}|[a-f0-9]{64})\b"),
    "PERSON": re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")
}

# Entity priorities to resolve overlap conflicts (e.g. Phone vs Email, Phone vs Name)
ENTITY_PRIORITIES = {
    "API_KEY": 3,
    "CREDIT_CARD": 3,
    "SSN": 3,
    "EMAIL": 2,
    "PHONE": 2,
    "IP": 2,
    "PERSON": 1,
    "LOCATION": 1,
    "OTHER": 0
}

# Synthetic replacement values pool
SYNTHETIC_POOLS = {
    "PERSON": [
        "Michael Smith", "Sarah Jenkins", "David Miller", "Emily Davis",
        "Robert Taylor", "Jessica Wilson", "James Thomas", "Karen Anderson",
        "Joseph Taylor", "Nancy Thomas", "Charles White", "Lisa Harris"
    ],
    "EMAIL": [
        "alex.jones@example.com", "maria.smith@test.org", "johndoe@domain.net",
        "sam.wilson@mail.co", "lisa.white@web.io", "robert.taylor@company.com"
    ],
    "PHONE": [
        "555-555-0101", "555-555-0102", "555-555-0103", "555-555-0104", "555-555-0105", "555-555-0106"
    ],
    "CREDIT_CARD": [
        "4111-1111-1111-1111", "5555-5555-5555-5555", "3782-822463-10005",
        "6011-1111-1111-1111"
    ],
    "SSN": [
        "000-12-3456", "999-88-7766", "123-45-6789", "888-77-6655"
    ],
    "IP": [
        "192.168.1.100", "10.0.0.50", "172.16.254.1", "8.8.8.8"
    ],
    "API_KEY": [
        "sk-proj-SyntheticApiKeyProd123456789012345678901234",
        "AIzaSySyntheticKeyHere12345678901234",
        "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    ],
    "LOCATION": [
        "New York", "London", "Paris", "Tokyo", "Berlin", "San Francisco"
    ]
}

def is_valid_luhn(card_number: str) -> bool:
    """Verifies a credit card string matches the Luhn checksum formula."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 16:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            double_digit = digit * 2
            if double_digit > 9:
                double_digit -= 9
            checksum += double_digit
        else:
            checksum += digit
    return checksum % 10 == 0

def get_synthetic_value(entity_type: str, index: int) -> str:
    """Gets a realistic mock value for synthetic mode anonymization."""
    pool = SYNTHETIC_POOLS.get(entity_type, ["SyntheticValue"])
    val = pool[index % len(pool)]
    if index >= len(pool):
        if "-" in val or "." in val:
            return f"{val}-{index}"
        return f"{val} {index}"
    return val

def resolve_overlaps(matches: List[Dict]) -> List[Dict]:
    """Resolves overlapping entity coordinates based on priority first, then match length."""
    # Sort matches by start position ascending, then priority descending, then length descending
    sorted_matches = sorted(
        matches, 
        key=lambda x: (x["start"], -ENTITY_PRIORITIES.get(x["entity_type"], 0), -(x["end"] - x["start"]))
    )
    keep = []
    last_end = -1
    for m in sorted_matches:
        if m["start"] >= last_end:
            keep.append(m)
            last_end = m["end"]
    return keep

def analyze_text(text: str) -> List[Dict]:
    """Scans the text for PII using Presidio or fallback Regex matching engines."""
    matches = []
    
    # 1. API Keys regex matching
    for match in REGEX_PATTERNS["API_KEY"].finditer(text):
        matches.append({
            "start": match.start(),
            "end": match.end(),
            "entity_type": "API_KEY",
            "score": 0.95
        })
        
    # 2. Main Scan
    if presidio_available and analyzer is not None:
        try:
            presidio_results = analyzer.analyze(text=text, language="en")
            for r in presidio_results:
                t = r.entity_type
                mapped_type = "OTHER"
                if t == "PERSON":
                    mapped_type = "PERSON"
                elif t == "EMAIL_ADDRESS":
                    mapped_type = "EMAIL"
                elif t == "PHONE_NUMBER":
                    mapped_type = "PHONE"
                elif t == "CREDIT_CARD":
                    mapped_type = "CREDIT_CARD"
                elif t == "US_SSN":
                    mapped_type = "SSN"
                elif t in ("IP_ADDRESS", "IP"):
                    mapped_type = "IP"
                elif t == "LOCATION":
                    mapped_type = "LOCATION"
                else:
                    mapped_type = t
                
                # Check validation check for Credit Card Luhn formula
                if mapped_type == "CREDIT_CARD":
                    cc_val = text[r.start:r.end]
                    if not is_valid_luhn(cc_val):
                        continue
                        
                matches.append({
                    "start": r.start,
                    "end": r.end,
                    "entity_type": mapped_type,
                    "score": r.score
                })
        except Exception as e:
            logger.warning(f"Presidio analysis failed: {e}. Falling back to Regex analyzer.")
            # Run Regex scan fallback
            for entity_type, pattern in REGEX_PATTERNS.items():
                if entity_type == "API_KEY":
                    continue
                for match in pattern.finditer(text):
                    val = text[match.start():match.end()]
                    if entity_type == "CREDIT_CARD" and not is_valid_luhn(val):
                        continue
                    matches.append({
                        "start": match.start(),
                        "end": match.end(),
                        "entity_type": entity_type,
                        "score": 0.85
                    })
    else:
        # Static Regex engine fallback
        for entity_type, pattern in REGEX_PATTERNS.items():
            if entity_type == "API_KEY":
                continue
            for match in pattern.finditer(text):
                val = text[match.start():match.end()]
                if entity_type == "CREDIT_CARD" and not is_valid_luhn(val):
                    continue
                matches.append({
                    "start": match.start(),
                    "end": match.end(),
                    "entity_type": entity_type,
                    "score": 0.85
                })
                
    return resolve_overlaps(matches)

def anonymize_text(text: str, mode: str = "mask") -> Tuple[str, Dict[str, str], int]:
    """Replaces detected PII values inside a string with placeholders or synthetic tokens."""
    if not text:
        return "", {}, 0
        
    matches = analyze_text(text)
    redacted_count = len(matches)
    
    # Process from right to left so indices don't shift
    sorted_matches = sorted(matches, key=lambda x: x["start"], reverse=True)
    
    mappings = {}
    original_to_anon = {}
    entity_counters = {}
    
    working_text = text
    for m in sorted_matches:
        start = m["start"]
        end = m["end"]
        entity_type = m["entity_type"]
        original_value = text[start:end]
        
        if original_value in original_to_anon:
            anon_token = original_to_anon[original_value]
        else:
            counter = entity_counters.get(entity_type, 0) + 1
            entity_counters[entity_type] = counter
            
            if mode == "synthetic":
                anon_token = get_synthetic_value(entity_type, counter - 1)
            else:
                anon_token = f"{{{{{entity_type}_{counter}}}}}"
                
            original_to_anon[original_value] = anon_token
            mappings[anon_token] = original_value
            
        working_text = working_text[:start] + anon_token + working_text[end:]
        
    return working_text, mappings, redacted_count

def restore_text(text: str, mappings: Dict[str, str]) -> str:
    """Restores original values, replacing longest placeholders first to avoid truncation conflicts."""
    if not text or not mappings:
        return text
        
    # Sort by length descending (longest placeholder first)
    sorted_placeholders = sorted(mappings.keys(), key=len, reverse=True)
    
    restored_text = text
    for placeholder in sorted_placeholders:
        original = mappings[placeholder]
        restored_text = restored_text.replace(placeholder, original)
        
    return restored_text

def anonymize_messages(messages: List[Dict], mode: str = "mask") -> Tuple[List[Dict], Dict[str, str], int]:
    """Helper to anonymize multiple messages collectively while sharing counters and states."""
    cumulative_mappings = {}
    original_to_anon = {}
    entity_counters = {}
    total_redacted = 0
    
    new_messages = []
    for msg in messages:
        new_msg = dict(msg)
        if "content" in new_msg and isinstance(new_msg["content"], str):
            text = new_msg["content"]
            matches = analyze_text(text)
            total_redacted += len(matches)
            
            sorted_matches = sorted(matches, key=lambda x: x["start"], reverse=True)
            working_text = text
            
            for m in sorted_matches:
                start = m["start"]
                end = m["end"]
                entity_type = m["entity_type"]
                original_value = text[start:end]
                
                if original_value in original_to_anon:
                    anon_token = original_to_anon[original_value]
                else:
                    counter = entity_counters.get(entity_type, 0) + 1
                    entity_counters[entity_type] = counter
                    
                    if mode == "synthetic":
                        anon_token = get_synthetic_value(entity_type, counter - 1)
                    else:
                        anon_token = f"{{{{{entity_type}_{counter}}}}}"
                        
                    original_to_anon[original_value] = anon_token
                    cumulative_mappings[anon_token] = original_value
                    
                working_text = working_text[:start] + anon_token + working_text[end:]
            new_msg["content"] = working_text
        new_messages.append(new_msg)
        
    return new_messages, cumulative_mappings, total_redacted
