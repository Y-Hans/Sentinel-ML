import pandas as pd

data = pd.read_csv("../data/data.csv")

def has_suspicious_words(url):
    keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update', 'crypto']
    return int(any(k in url.lower() for k in keywords))

def special_char_ratio(url):
    special = sum(not c.isalnum() for c in url)
    return special / len(url)

def digit_ratio(url):
    digits = sum(c.isdigit() for c in url)
    return digits / len(url)

def has_at_symbol(url):
    return int('@' in url)

# Build dataset
df = pd.DataFrame()

df['url'] = data['URL']
df['URLLength'] = data['URLLength']
df['DomainLength'] = data['DomainLength']
df['IsDomainIP'] = data['IsDomainIP']
df['NoOfSubDomain'] = data['NoOfSubDomain']
df['IsHTTPS'] = data['IsHTTPS']

# NEW FEATURES
df['HasSuspiciousWords'] = df['url'].apply(has_suspicious_words)
df['SpecialCharRatio'] = df['url'].apply(special_char_ratio)
df['DigitRatio'] = df['url'].apply(digit_ratio)
df['HasAtSymbol'] = df['url'].apply(has_at_symbol)

df['label'] = data['label']

df = df.dropna()

df.to_csv("../data/cleaned_data.csv", index=False)

print("✅ Updated dataset saved")