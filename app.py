import hashlib
import random
import re
import sqlite3
import string
import streamlit as st

# --- 1. Database Setup for Uniqueness / Reuse Check ---
conn = sqlite3.connect("passwords.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute(
    "CREATE TABLE IF NOT EXISTS history (hash_val TEXT PRIMARY KEY)"
)
conn.commit()


def check_password_reuse(password):
  """Checks if the password hash already exists in the database."""
  pwd_hash = hashlib.sha256(password.encode()).hexdigest()
  cursor.execute("SELECT * FROM history WHERE hash_val = ?", (pwd_hash,))
  if cursor.fetchone():
    return (
        False,
        "⚠️ This password has been used before! Please choose a unique one.",
    )
  else:
    # Save the new password hash to history
    cursor.execute("INSERT OR IGNORE INTO history VALUES (?)", (pwd_hash,))
    conn.commit()
    return True, "✅ Password is unique (not found in past history)."


# --- 2. Core Analysis Logic ---
def analyze_password(password):
  score = 0
  feedback = []

  # Length Check
  if len(password) < 8:
    feedback.append("❌ Password is too short (less than 8 characters).")
  elif len(password) >= 12:
    score += 2
    feedback.append("✔️ Great length (12+ characters).")
  else:
    score += 1
    feedback.append("⚠️ Good length, but 12+ characters is safer.")

  # Complexity Checks
  if re.search(r"[A-Z]", password):
    score += 1
    feedback.append("✔️ Contains uppercase letters.")
  else:
    feedback.append("❌ Missing uppercase letters (A-Z).")

  if re.search(r"[a-z]", password):
    score += 1
    feedback.append("✔️ Contains lowercase letters.")
  else:
    feedback.append("❌ Missing lowercase letters (a-z).")

  if re.search(r"\d", password):
    score += 1
    feedback.append("✔️ Contains numbers.")
  else:
    feedback.append("❌ Missing numbers (0-9).")

  if re.search(r"[@$!%*?&]", password):
    score += 1
    feedback.append("✔️ Contains special characters.")
  else:
    feedback.append("❌ Missing special characters (e.g., @, $, !, %, *, ?, &).")

  # Uniqueness Check
  is_unique, uniqueness_msg = check_password_reuse(password)
  feedback.append(uniqueness_msg)
  if is_unique:
    score += 1

  # Final Strength Evaluation
  if score >= 6:
    strength = "Strong 🟢"
  elif score >= 4:
    strength = "Moderate 🟡"
  else:
    strength = "Weak 🔴"

  return strength, feedback


# --- 3. Strong Password Generator ---
def suggest_password():
  length = 12
  chars = (
      string.ascii_lowercase
      + string.ascii_uppercase
      + string.digits
      + "@$!%*?&"
  )
  while True:
    pwd = "".join(random.choice(chars) for _ in range(length))
    if (
        re.search(r"[A-Z]", pwd)
        and re.search(r"[a-z]", pwd)
        and re.search(r"\d", pwd)
        and re.search(r"[@$!%*?&]", pwd)
    ):
      return pwd


# --- 4. Streamlit Web Interface ---
st.set_page_config(
    page_title="Password Strength Analyzer", page_icon="🔒", layout="centered"
)

st.title("🔒 Password Strength Analyzer")
st.write(
    "Evaluate your password's length, complexity, uniqueness, and check for"
    " reuse history."
)

user_password = st.text_input(
    "Enter a password to test:", type="password", help="Type any password here"
)

if user_password:
  strength, feedback = analyze_password(user_password)

  st.markdown("---")
  st.subheader(f"Strength Result: {strength}")

  st.write("**Detailed Feedback:**")
  for item in feedback:
    st.write(f"- {item}")

  if strength != "Strong 🟢":
    st.markdown("---")
    st.warning("Your password could be stronger.")
    if st.button("Generate Secure Alternative"):
      secure_suggestion = suggest_password()
      st.code(secure_suggestion, language="")
      st.info("Copy this generated suggestion and try it out!")
