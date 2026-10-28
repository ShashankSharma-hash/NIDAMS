"""Convert access_log.jsonl -> labeled CSV and print a quick summary."""
import pandas as pd

df = pd.read_json("access_log.jsonl", lines=True)
df = df.sort_values("ts").reset_index(drop=True)
df.to_csv("logs_labeled.csv", index=False)
print("rows:", len(df))
print(df["label"].value_counts())
print("\nstatus codes per label:")
print(pd.crosstab(df["label"], df["status"]))
print("\nrequests per IP (by label, mean):")
print(df.groupby(["label", "ip"]).size().groupby("label").mean().round(1))
