# 🔐 Password Security Tool

A web-based password analysis tool that evaluates password strength using real-world security concepts like entropy, pattern detection, and breach checking.

---

## 🚀 Features

* 🔎 **Password Strength Analysis**

  * Calculates entropy to estimate unpredictability
  * Classifies passwords from *Very Weak → Strong*

* ⚠️ **Pattern Detection**

  * Detects common weak patterns (e.g., `1234`, `aaaa`, `qwerty`)

* 📚 **Dictionary Check**

  * Flags commonly used passwords like `password`, `admin`

* 🌐 **Breach Detection**

  * Uses Have I Been Pwned API (k-anonymity model)
  * Checks if password appeared in real-world data leaks

* ⏱️ **Crack Time Estimation**

  * Estimates time required for brute-force attacks

* 🔐 **Password Generator**

  * Generates strong random passwords with symbols, numbers, and mixed case

* 👁️ **Show/Hide Password**

  * Toggle password visibility

---

## 🧠 How It Works

### 1. Entropy Calculation

Measures how unpredictable a password is based on length and character variety.

* Example:

  * `password123` → Low entropy
  * `T!g9#LpQ2@zX` → High entropy

---

### 2. Pattern Detection

Identifies predictable sequences attackers commonly use.

* Example:

  * `aaaa1234` → Weak
  * `qwerty@123` → Weak

---

### 3. Breach Check (Real-world security)

* Password is converted to SHA-1 hash
* Only partial hash is sent to API (privacy-safe)
* API checks if password exists in leaked databases

---

### 4. Crack Time Estimation

Calculates how long it would take to crack a password.

* Weak passwords → seconds
* Strong passwords → years

---

## 🛠️ Technologies Used

* HTML5
* CSS3
* JavaScript (Vanilla JS)
* Web Crypto API (SHA-1 hashing)
* Have I Been Pwned API

---

## 📂 Project Structure

```
project/
│── index.html
│── style.css
│── script.js
```

---

## ▶️ How to Run

1. Download or clone the repository
2. Open `index.html` in your browser
3. Enter a password and see the analysis

---

## ⚠️ Limitations

* Entropy model is simplified (not full attack simulation)
* Pattern detection is basic
* Password generator is not cryptographically secure

---

## 🔥 Future Improvements

* Integrate zxcvbn for better strength estimation
* Add real GPU-based crack simulation
* Improve password generator using secure randomness
* Add UI improvements and accessibility

---

## 👨‍💻 Author

**Chekuri Satyanarayana Raja Varma**

---

## 📌 Project Goal

To demonstrate how password strength is evaluated in real-world systems and educate users on creating secure passwords.
