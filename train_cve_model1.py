from sentence_transformers import SentenceTransformer, InputExample, losses
from torch.utils.data import DataLoader
import pandas as pd
import os

def fine_tune_cve_model(
    csv_path: str,
    model_name: str = "basel/ATTACK-BERT",  # or 'all-MiniLM-L6-v2'
    output_path: str = "./rhel_cve_model",
    batch_size: int = 16,
    epochs: int = 3,
    warmup_steps: int = 100,
    show_progress_bar: bool = True,
    clean_text: bool = True
):
    """
    Fine-tunes a Sentence-BERT model on RHEL package and CVE description pairs.

    Args:
        csv_path (str): Path to CSV file with 'pkg_info' and 'cve_description' columns.
        model_name (str): HuggingFace model name to use for fine-tuning.
        output_path (str): Directory where fine-tuned model will be saved.
        batch_size (int): Training batch size.
        epochs (int): Number of training epochs.
        warmup_steps (int): Warmup steps for learning rate scheduler.
        show_progress_bar (bool): Whether to show the training progress bar.
        clean_text (bool): Remove CVE IDs like CVE-XXXX-YYYY from descriptions.

    Returns:
        SentenceTransformer: The fine-tuned model.
    """
    # Load data
    df = pd.read_csv(csv_path)

    # Optional: Clean CVE ID prefixes from descriptions
    def strip_cve_id(desc):
        return ' '.join(word for word in desc.split() if not word.upper().startswith("CVE-"))

    if clean_text:
        df["cve_description"] = df["cve_description"].apply(strip_cve_id)

    # Build training examples
    train_examples = [
        InputExample(texts=[row.pkg_info, row.cve_description])
        for _, row in df.iterrows()
    ]

    # Load base model
    model = SentenceTransformer(model_name)

    # Prepare DataLoader and loss
    train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=batch_size)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    # Train
    model.fit(
        train_objectives=[(train_dataloader, train_loss)],
        epochs=epochs,
        warmup_steps=warmup_steps,
        show_progress_bar=show_progress_bar
    )

    # Save
    model.save(output_path)
    print(f"✅ Fine-tuned model saved to: {output_path}")

    return model