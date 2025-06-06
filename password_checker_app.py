import streamlit as st
import re
import hashlib
import requests

def check_password_strength(password):
    length = len(password) >= 8
    upper = re.search(r"[A-Z]", password)
    lower = re.search(r"[a-z]", password)
    digit = re.search(r"\d", password)
    special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])
    
    if score == 5:
        return "🟢 Very Strong"
    elif score == 4:
        return "🟡 Strong"
    elif score == 3:
        return "🟠 Moderate"
    else:
        return "🔴 Weak"

def check_pwned_api(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

# Streamlit UI
st.title("🔐 Password Strength Checker")

password = st.text_input("Enter your password", type="password")

if password:
    strength = check_password_strength(password)
    st.write(f"**Strength:** {strength}")
    
    with st.spinner("Checking breaches..."):
        breach_count = check_pwned_api(password)
        if breach_count:
            st.error(f"⚠️ This password has appeared in {breach_count} known data breaches.")
        else:
            st.success("✅ This password is safe and not found in breaches.")
