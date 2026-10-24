# Sentinel Fresh URL Model Evaluation

- Model: `SENTINEL_FRESH_URL_20261024`
- Final-test SHA-256: `92e634a2a21b8e7d35d37e2db0c006314d5b9226eba8cb66c6028e8ce70d6446`
- Threshold: `0.946000` (selected on validation only)
- Malicious recall: `0.9808`
- Benign false-positive rate: `0.1847`
- Precision: `0.9302`
- F1: `0.9548`
- Confusion matrix: `{'tn': 203, 'fp': 46, 'fn': 12, 'tp': 613}`
- Python inference: `0.001345 ms/url` averaged over repeated final-test batches

## Slices

- **short_url**: {'malicious_recall': 0.9868204283360791, 'benign_false_positive_rate': 0.2222222222222222, 'precision': 0.9286821705426357, 'f1': 0.9568690095846646, 'confusion_matrix': {'tn': 161, 'fp': 46, 'fn': 8, 'tp': 599}, 'row_count': 814}
- **long_url**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 5, 'fp': 0, 'fn': 1, 'tp': 0}, 'row_count': 6}
- **brand_impersonation**: {'malicious_recall': 1.0, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 1.0, 'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 0, 'tp': 186}, 'row_count': 186}
- **ip_based_url**: {'malicious_recall': 1.0, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 1.0, 'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 0, 'tp': 54}, 'row_count': 54}
- **executable_payload_path**: {'malicious_recall': 0.875, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 0.9333333333333333, 'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 1, 'tp': 7}, 'row_count': 8}
- **financial_login_verification**: {'malicious_recall': 1.0, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 1.0, 'confusion_matrix': {'tn': 8, 'fp': 0, 'fn': 0, 'tp': 8}, 'row_count': 16}
- **legitimate_developer_media_documentation**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.18473895582329317, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 203, 'fp': 46, 'fn': 0, 'tp': 0}, 'row_count': 249}

## Per source

- **Apache Software Foundation**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 1.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 0, 'fp': 9, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Apple**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **BBC**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Bank of America**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Chase**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Cloudflare**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.1111111111111111, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 8, 'fp': 1, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Disney**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Django**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 1.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 0, 'fp': 9, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Etsy**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **European Union**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **GNU**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 1.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 0, 'fp': 9, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Kotlin**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.1111111111111111, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 8, 'fp': 1, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Linux Kernel**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.7777777777777778, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 2, 'fp': 7, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Mastercard**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **Microsoft**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **NASA**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Netflix**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Netlify**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **PayPal**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Pinterest**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Python**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 1.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 0, 'fp': 1, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **Python Documentation**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 1.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 0, 'fp': 7, 'fn': 0, 'tp': 0}, 'row_count': 7}
- **Python Package Index**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Reuters**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **Salesforce**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.1111111111111111, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 8, 'fp': 1, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Stack Overflow**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **Target**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.1111111111111111, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 8, 'fp': 1, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **TechCrunch**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **The Guardian**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **TikTok**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **TweetFeed**: {'malicious_recall': 0.9864864864864865, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 0.9931972789115646, 'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 7, 'tp': 511}, 'row_count': 518}
- **USA.gov**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **United Nations**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **Walmart**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **YouTube**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 9, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 9}
- **npm**: {'malicious_recall': 0.0, 'benign_false_positive_rate': 0.0, 'precision': 0.0, 'f1': 0.0, 'confusion_matrix': {'tn': 1, 'fp': 0, 'fn': 0, 'tp': 0}, 'row_count': 1}
- **phishunt.io**: {'malicious_recall': 0.9532710280373832, 'benign_false_positive_rate': 0.0, 'precision': 1.0, 'f1': 0.9760765550239234, 'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 5, 'tp': 102}, 'row_count': 107}
