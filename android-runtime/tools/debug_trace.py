import pickle, json, numpy as np

clf = pickle.load(open('Messages-ml/champion_v2_model.pkl', 'rb'))
kt = json.load(open('debug_s01_kt.json'))
scaled_vec = np.array(kt['scaled'], dtype=np.float64)

binned = clf._bin_mapper.transform(scaled_vec.reshape(1, -1))[0]

scores = np.array(clf._baseline_prediction[0], dtype=np.float64)
for iter_idx in range(len(clf._predictors)):
    for k in range(3):
        tree = clf._predictors[iter_idx][k]
        node_idx = 0
        while True:
            node = tree.nodes[node_idx]
            if node['is_leaf']:
                scores[k] += node['value']
                break
            feat_idx = int(node['feature_idx'])
            bin_thresh = int(node['bin_threshold'])
            b_val = binned[feat_idx]
            if b_val <= bin_thresh:
                node_idx = int(node['left'])
            else:
                node_idx = int(node['right'])

print("=== Iteration 1 Class 0 in Python ===")
tree = clf._predictors[1][0]
node_idx = 0
while True:
    node = tree.nodes[node_idx]
    if node['is_leaf']:
        print(f"Leaf value = {node['value']}, node_idx={node_idx}")
        break
    feat_idx = int(node['feature_idx'])
    bin_thresh = int(node['bin_threshold'])
    b_val = binned[feat_idx]
    thresh_float = clf._bin_mapper.bin_thresholds_[feat_idx][bin_thresh] if bin_thresh < len(clf._bin_mapper.bin_thresholds_[feat_idx]) else 999.0
    print(f"Node {node_idx}: feat {feat_idx} (scaled_val={scaled_vec[feat_idx]}, bin {b_val} vs thresh {bin_thresh}, thresh_float={thresh_float})")
    if b_val <= bin_thresh:
        node_idx = int(node['left'])
    else:
        node_idx = int(node['right'])