from sentence_transformers import SentenceTransformer, util

# Load the fine-tuned model
model = SentenceTransformer('./rhel_cve_model')

# Example: predict similarity between a RHEL package and multiple CVEs
query = "glibc 2.28 core GNU libraries"
cve_list = [
    "CVE-2022-1234: glibc buffer overflow vulnerability",
    "CVE-2023-1111: openssl heap overflow in TLS handler",
    "CVE-2021-2222: kernel race condition in TCP stack",
    "CVE-2020-9999: PostgreSQL privilege escalation"
]

# Encode query and list
query_embedding = model.encode(query, convert_to_tensor=True)
cve_embeddings = model.encode(cve_list, convert_to_tensor=True)

# Compute cosine similarities
similarities = util.cos_sim(query_embedding, cve_embeddings)

# Rank and print
print(f"\nSimilarity scores for query: {query}\n")
for i, score in enumerate(similarities[0]):
    print(f"{cve_list[i]} => Similarity: {score.item():.4f}")