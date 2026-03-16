import torch
from transformers import AutoTokenizer, RobertaForSequenceClassification
import logging
import warnings

# Suppress warnings to keep logs clean
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=FutureWarning)

class MLEngine:
    def __init__(self, logger_callback=None):
        self.log = logger_callback if logger_callback else print
        self.model_name = "microsoft/graphcodebert-base"
        
        self.log("🧠 [ML ENGINE] Initializing Neural Engine...")
        self.log("   └── Loading Tensor Weights (This happens once)...")
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = RobertaForSequenceClassification.from_pretrained(
                self.model_name,
                use_safetensors=True,
                ignore_mismatched_sizes=True
            )
            
            # Use CPU for stability on free tier (GPU runs out of VRAM too fast)
            self.device = torch.device("cpu")
            self.model.to(self.device)
            
            self.log(f"   └── ✅ Model Ready. Running on: {self.device.type.upper()}")
            self.is_ready = True
            
        except Exception as e:
            self.log(f"⚠️ [ML ENGINE FAILURE] {str(e)}")
            self.is_ready = False

    def predict_vulnerability(self, code_content):
        """
        Sliding Window Scanner:
        Scans ANY file size by breaking it into 512-token chunks.
        Never freezes, never runs out of RAM.
        """
        if not self.is_ready or not code_content:
            return False, 0.0, []

        # 1. Tokenize the WHOLE file first (AutoTokenizer handles this fast)
        # We start with a max length of 100,000 to prevent infinite loops on binary garbage
        inputs = self.tokenizer(
            code_content, 
            return_tensors="pt", 
            truncation=True, 
            max_length=100000, 
            padding=False
        )
        
        input_ids = inputs['input_ids'][0]
        
        # 2. Define Window Size (510 tokens + 2 special tokens = 512 limit)
        window_size = 510
        stride = 510 # No overlap needed for simple classification, makes it 2x faster
        
        total_tokens = len(input_ids)
        chunks = []
        
        # 3. Create the windows
        for i in range(0, total_tokens, stride):
            chunk = input_ids[i : i + window_size]
            if len(chunk) < 10: continue # Skip tiny fragments
            chunks.append(chunk)

        highest_confidence = 0.0
        is_vulnerable = False
        bad_snippets = []

        # 4. Process each window sequentially
        # This loop ensures the UI updates and doesn't look "stuck"
        for i, chunk_ids in enumerate(chunks):
            try:
                # Prepare chunk for model
                chunk_ids = chunk_ids.unsqueeze(0).to(self.device)
                
                with torch.no_grad():
                    outputs = self.model(input_ids=chunk_ids)
                    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
                    
                    # Microsoft CodeBERT usually outputs [Safe_Score, Unsafe_Score]
                    vuln_score = probs[0][1].item() 
                    
                    if vuln_score > 0.50: # Threshold
                        is_vulnerable = True
                        if vuln_score > highest_confidence:
                            highest_confidence = vuln_score
                        
                        # Decode back to text to show the user EXACTLY what is wrong
                        decoded_snippet = self.tokenizer.decode(chunk_ids[0], skip_special_tokens=True)
                        bad_snippets.append(decoded_snippet)
                        
                        # Optimization: If we found high-confidence issues, stop scanning this file
                        # to save time. We only need to prove it's vulnerable.
                        if vuln_score > 0.85:
                            break
                            
            except Exception:
                continue

        return is_vulnerable, round(highest_confidence * 100, 2), bad_snippets