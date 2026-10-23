"""V7 Production Classifier Definition."""
from __future__ import annotations
import numpy as np


class V7GatedURLClassifier:
    """Production release model packaging the underlying classifier and safe-domain adjudication."""
    def __init__(self, base_model, feature_names: list[str], threshold: float, conf_bound: float = 0.80):
        self.base_model = base_model
        self.feature_names = feature_names
        self.threshold = threshold
        self.conf_bound = conf_bound
        
        self.idx_safe_brand = feature_names.index("Safe_Brand_Domain")
        self.idx_brand_imp = feature_names.index("BrandImpersonationScore")
        self.idx_susp_tld = feature_names.index("SuspiciousTLD")
        self.idx_is_ip = feature_names.index("IsDomainIP")
        self.idx_susp_ext = feature_names.index("PathSuspiciousExtension")
        self.idx_redirect = feature_names.index("QueryRedirect")
        self.idx_path_words = feature_names.index("PathSuspiciousWords")
        self.idx_query_words = feature_names.index("QuerySuspiciousWords")
        self.idx_double_enc = feature_names.index("PathDoubleEncoded")
        self.idx_at = feature_names.index("HasAtSymbol")
        self.idx_subdomain = feature_names.index("NoOfSubDomain")
        self.idx_puny = feature_names.index("HostPunycode")
        self.idx_port = feature_names.index("HasPort")
        self.idx_slashes = feature_names.index("PathConsecutiveSlashes")
        self.idx_non_ascii = feature_names.index("HasNonAscii")
        self.idx_nested_url = feature_names.index("HasNestedURL")

    def _apply_gating(self, raw_probs: np.ndarray, mat: np.ndarray) -> np.ndarray:
        has_threat = (
            (mat[:, self.idx_brand_imp] > 0) |
            (mat[:, self.idx_susp_tld] > 0) |
            (mat[:, self.idx_is_ip] > 0) |
            (mat[:, self.idx_susp_ext] > 0) |
            (mat[:, self.idx_redirect] > 0) |
            (mat[:, self.idx_path_words] > 0) |
            (mat[:, self.idx_query_words] > 0) |
            (mat[:, self.idx_double_enc] > 0) |
            (mat[:, self.idx_at] > 0) |
            (mat[:, self.idx_puny] > 0) |
            (mat[:, self.idx_port] > 0) |
            (mat[:, self.idx_slashes] > 0) |
            (mat[:, self.idx_non_ascii] > 0) |
            (mat[:, self.idx_nested_url] > 0) |
            (mat[:, self.idx_subdomain] >= 2)
        )
        is_safe_brand = (mat[:, self.idx_safe_brand] == 1.0) & (~has_threat)
        p_final = np.copy(raw_probs)
        mask = is_safe_brand & (raw_probs < self.conf_bound)
        p_final[mask] = 0.001
        return p_final

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        raw_p = self.base_model.predict_proba(X)[:, 1]
        p1 = self._apply_gating(raw_p, X)
        return np.column_stack([1.0 - p1, p1])

    def predict(self, X: np.ndarray) -> np.ndarray:
        p1 = self.predict_proba(X)[:, 1]
        return (p1 >= self.threshold).astype(int)
