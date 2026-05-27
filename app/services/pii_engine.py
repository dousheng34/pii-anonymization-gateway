import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("pii_gateway.pii_engine")

# Try to import Microsoft Presidio
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    
    # Configure Presidio to use the lightweight en_core_web_sm model instead of the default large model
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
        f"Microsoft Presidio or spaCy model 'en_core_web_sm' failed to load: {e}. "
        "Falling back to Regex-only mode."
    )
    presidio_available = False
    analyzer = None

# Custom Regex patterns for offline/fallback mode
REGEX_PATTERNS = {
    "EMAIL": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IP": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "API_KEY": re.compile(r"\b(?:sk-[a-zA-Z0-9]{48}|AIzaSy[a-zA-Z0-9-_]{33}|[a-f0-9]{32}|[a-f0-9]{64})\b"),
    "PERSON": re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")  # Basic name matcher
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
        "555-0101", "555-0102", "555-0103", "555-0104", "555-0105", "555-0106"
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

def get_synthetic_value(entity_type: str, index: int) -> str:
    """Generate realistic fake data for a given entity type and index."""
    pool = SYNTHETIC_POOLS.get(entity_type, ["SyntheticValue"])
    val = pool[index % len(pool)]
    if index >= len(pool):
        if "-" in val or "." in val:
            return f"{val}-{index}"
        return f"{val} {index}"
    return val

def resolve_overlaps(matches: List[Dict]) -> List[Dict]:
    """Resolve overlapping matches by selecting the longest or earliest match first."""
    # Sort matches by start position ascending, then by length descending
    sorted_matches = sorted(matches, key=lambda x: (x["start"], -(x["end"] - x["start"])))
    keep = []
    last_end = -1
    for m in sorted_matches:
        if m["start"] >= last_end:
            keep.append(m)
            last_end = m["end"]
    return keep

def analyze_text(text: str) -> List[Dict]:
    """Analyze text for PII using Presidio (if available) with Regex fallbacks."""
    matches = []
    
    # Always run the API_KEY regex since Presidio doesn't recognize API keys by default
    for match in REGEX_PATTERNS["API_KEY"].finditer(text):
        matches.append({
            "start": match.start(),
            "end": match.end(),
            "entity_type": "API_KEY",
            "score": 0.95
        })
        
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
                
                matches.append({
                    "start": r.start,
                    "end": r.end,
                    "entity_type": mapped_type,
                    "score": r.score
                })
        except Exception as e:
            logger.warning(f"Presidio analysis failed: {e}. Falling back to Regex analyzer.")
            # Fallback to regex analyzer for non-API_KEY patterns
            for entity_type, pattern in REGEX_PATTERNS.items():
                if entity_type == "API_KEY":
                    continue
                for match in pattern.finditer(text):
                    matches.append({
                        "start": match.start(),
                        "end": match.end(),
                        "entity_type": entity_type,
                        "score": 0.85
                    })
    else:
        # Full Regex fallback mode
        for entity_type, pattern in REGEX_PATTERNS.items():
            if entity_type == "API_KEY":
                continue
            for match in pattern.finditer(text):
                matches.append({
                    "start": match.start(),
                    "end": match.end(),
                    "entity_type": entity_type,
                    "score": 0.85
                })
                
    return resolve_overlaps(matches)

def anonymize_text(text: str, mode: str = "mask") -> Tuple[str, Dict[str, str], int]:
    """
    Anonymize text by replacing PII with typed tokens or synthetic substitutes.
    Returns:
        anonymized_text: The cleaned prompt text.
        mappings: A dictionary mapping placeholder -> original_value.
        redacted_count: The total count of redacted entities.
    """
    if not text:
        return "", {}, 0
        
    matches = analyze_text(text)
    redacted_count = len(matches)
    
    # Sort matches in reverse order so we can replace substrings without shifting indices
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
        
        # Consistent mapping: check if we already replaced this exact string in this text
        if original_value in original_to_anon:
            anon_token = original_to_anon[original_value]
        else:
            # Get the counter for this entity type to generate PERSON_1, PERSON_2, etc.
            counter = entity_counters.get(entity_type, 0) + 1
            entity_counters[entity_type] = counter
            
            if mode == "synthetic":
                anon_token = get_synthetic_value(entity_type, counter - 1)
            else:  # "mask"
                anon_token = f"{{{{{entity_type}_{counter}}}}}"
                
            original_to_anon[original_value] = anon_token
            mappings[anon_token] = original_value
            
        working_text = working_text[:start] + anon_token + working_text[end:]
        
    return working_text, mappings, redacted_count

def restore_text(text: str, mappings: Dict[str, str]) -> str:
    """
    Restore the original PII values back into the text by substituting placeholders/aliases.
    Performs replacements in order of descending length (longest first) to prevent collisions.
    """
    if not text or not mappings:
        return text
        
    # Sort placeholders by length descending to prevent sub-string replacement bugs (longest first)
    sorted_placeholders = sorted(mappings.keys(), key=len, reverse=True)
    
    restored_text = text
    for placeholder in sorted_placeholders:
        original = mappings[placeholder]
        restored_text = restored_text.replace(placeholder, original)
        
    return restored_text

def anonymize_messages(messages: List[Dict], mode: str = "mask") -> Tuple[List[Dict], Dict[str, str], int]:
    """
    Anonymize a list of message objects, keeping mapping state consistent across all messages.
    """
    cumulative_mappings = {}
    original_to_anon = {}
    entity_counters = {}
    total_redacted = 0
    
    new_messages = []
    for msg in messages:
        # Shallow copy of message to avoid mutating the original request
        new_msg = dict(msg)
        if "content" in new_msg and isinstance(new_msg["content"], str):
            text = new_msg["content"]
            matches = analyze_text(text)
            total_redacted += len(matches)
            
            # Sort matches in reverse order so we replace from right to left
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

