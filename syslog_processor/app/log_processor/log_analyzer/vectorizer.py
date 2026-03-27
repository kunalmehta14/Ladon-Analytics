from typing import List, Union
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import onnxruntime as ort
from transformers import AutoTokenizer

class TFIDFTemplateExtractor:
	def __init__(self, stop_words='english', max_features=1000):
		self.vectorizer = TfidfVectorizer(stop_words=stop_words, max_features=max_features)
		self.model = None

	def process(self, data_list):
		df = pd.DataFrame(data_list)
		tfidf_matrix = self.vectorizer.fit_transform(df['line'])
		self.model = self.vectorizer
		template_grouping = df.groupby('line').agg({
			'log_id': list,
			'file': lambda x: list(set(x))
		}).reset_index()
		unique_templates = template_grouping.rename(columns={
			'line': 'template',
			'log_id': 'log_ids',
			'file': 'files'
		}).to_dict('records') 
		return unique_templates, self.model

	def get_model(self):
		return self.model

class ONNXTemplateVectorizer:
    def __init__(self, model_path, tokenizer_name='sentence-transformers/all-MiniLM-L12-v2'):
        # Use CPU execution for transformers
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            model_path, 
            sess_options, 
            providers=['CPUExecutionProvider']
        )
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)        
        # Get expected input names from the ONNX model to avoid mismatch errors
        self.input_names = [i.name for i in self.session.get_inputs()]

    def process(self, data_list):
        ids = [item[0] for item in data_list]
        lines = [item[1] for item in data_list]
        # Tokenization
        encoded = self.tokenizer(lines, padding=True, truncation=True, return_tensors='np')
        # Prepare inputs based on what the specific ONNX model expects
        onnx_inputs = {
            "input_ids": encoded['input_ids'].astype(np.int64),
            "attention_mask": encoded['attention_mask'].astype(np.int64)
        }
        # Only add token_type_ids if the model was exported with them
        if "token_type_ids" in self.input_names:
            onnx_inputs["token_type_ids"] = encoded.get(
                'token_type_ids', 
                np.zeros_like(encoded['input_ids'])
            ).astype(np.int64)
        # Inference
        model_output = self.session.run(None, onnx_inputs)
        last_hidden_state = model_output[0] 

        # Mean Pooling Logic
        mask = np.expand_dims(onnx_inputs['attention_mask'], -1)
        sum_embeddings = np.sum(last_hidden_state * mask, axis=1)
        sum_mask = np.clip(mask.sum(axis=1), a_min=1e-9, a_max=None)
        norm_embeddings = sum_embeddings / sum_mask

        # Return list of dicts: [{template_id, vector}, ...]
        return [
            {"template_id": ids[i], "vector": norm_embeddings[i].tolist()}
            for i in range(len(ids))
        ]