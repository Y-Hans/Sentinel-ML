from __future__ import annotations
import json, pickle, sys
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from feature_config import FeatureConfig
from feature_extraction import get_feature_names

MODELS_DIR = ROOT
ASSETS_DIR = ROOT.parent / 'android-runtime' / 'messages' / 'assets'

def export_all():
    print('Loading frozen Champion V2 artifacts...')
    tw = pickle.load(open(MODELS_DIR / 'champion_v2_tfidf_word.pkl', 'rb'))
    tc = pickle.load(open(MODELS_DIR / 'champion_v2_tfidf_char.pkl', 'rb'))
    sc = pickle.load(open(MODELS_DIR / 'champion_v2_scaler.pkl', 'rb'))
    clf = pickle.load(open(MODELS_DIR / 'champion_v2_model.pkl', 'rb'))
    
    cfg = FeatureConfig()
    det_names = get_feature_names(cfg)
    
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    
    word_bundle = {
        'version': '2.0.0',
        'n_features': len(tw.vocabulary_),
        'ngram_range': list(tw.ngram_range),
        'stop_words': sorted(list(tw.get_stop_words())),
        'token_pattern': '(?u)\\b\\w\\w+\\b',
        'norm': tw.norm,
        'sublinear_tf': tw.sublinear_tf,
        'vocabulary': {k: int(v) for k, v in tw.vocabulary_.items()},
        'idf': tw.idf_.tolist(),
    }
    w_path = ASSETS_DIR / 'champion_v2_word_vocab_idf.json'
    w_json = json.dumps(word_bundle, separators=(',', ':'))
    w_path.write_text(w_json, encoding='utf-8')
    print(f'Exported Word TF-IDF: {w_path} ({len(w_json)/1024:.2f} KB, {len(tw.vocabulary_)} tokens)')
    
    char_bundle = {
        'version': '2.0.0',
        'n_features': len(tc.vocabulary_),
        'analyzer': tc.analyzer,
        'ngram_range': list(tc.ngram_range),
        'norm': tc.norm,
        'sublinear_tf': tc.sublinear_tf,
        'vocabulary': {k: int(v) for k, v in tc.vocabulary_.items()},
        'idf': tc.idf_.tolist(),
    }
    c_path = ASSETS_DIR / 'champion_v2_char_vocab_idf.json'
    c_json = json.dumps(char_bundle, separators=(',', ':'))
    c_path.write_text(c_json, encoding='utf-8')
    print(f'Exported Char TF-IDF: {c_path} ({len(c_json)/1024:.2f} KB, {len(tc.vocabulary_)} n-grams)')
    
    scaler_bundle = {
        'version': '2.0.0',
        'n_features': int(sc.n_features_in_),
        'mean': sc.mean_.tolist(),
        'scale': sc.scale_.tolist(),
        'var': sc.var_.tolist(),
    }
    s_path = ASSETS_DIR / 'champion_v2_scaler.json'
    s_json = json.dumps(scaler_bundle, separators=(',', ':'))
    s_path.write_text(s_json, encoding='utf-8')
    print(f'Exported Scaler: {s_path} ({len(s_json)/1024:.2f} KB, {sc.n_features_in_} features)')
    
    trees_data = []
    for iter_idx in range(len(clf._predictors)):
        iter_classes = []
        for k in range(3):
            tree = clf._predictors[iter_idx][k]
            nodes_list = []
            for node in tree.nodes:
                nodes_list.append([
                    int(node['feature_idx']),
                    int(node['bin_threshold']),
                    int(node['left']),
                    int(node['right']),
                    float(node['value']),
                    int(node['is_leaf']),
                    int(node['missing_go_to_left']),
                ])
            iter_classes.append(nodes_list)
        trees_data.append(iter_classes)
        
    tree_bundle = {
        'version': '2.0.0',
        'model_type': 'HistGradientBoostingClassifier',
        'n_classes': 3,
        'n_iterations': len(trees_data),
        'n_trees_total': len(trees_data) * 3,
        'learning_rate': float(clf.learning_rate),
        'baseline_prediction': clf._baseline_prediction.tolist(),
        'decision_threshold': 0.704,
        'class_labels': ['BENIGN', 'SUSPICIOUS_SPAM', 'MALICIOUS'],
        'deterministic_features': det_names,
        'bin_thresholds': [arr.tolist() for arr in clf._bin_mapper.bin_thresholds_],
        'trees': trees_data,
    }
    t_path = ASSETS_DIR / 'champion_v2_trees.json'
    t_json = json.dumps(tree_bundle, separators=(',', ':'))
    t_path.write_text(t_json, encoding='utf-8')
    print(f'Exported Trees: {t_path} ({len(t_json)/1024:.2f} KB, {len(trees_data)*3} trees)')
    
    total_kb = (len(w_json) + len(c_json) + len(s_json) + len(t_json)) / 1024
    print(f'=== Total Messages-ML Android Assets: {total_kb:.2f} KB ({total_kb/1024:.2f} MB) ===')

if __name__ == '__main__':
    export_all()
