from typing import re


def calculate_password_strength(password: str) -> int:
    # Vérification de la longueur minimale
    length_score = len(password) >= 8

    # Critères de complexité
    has_lowercase = bool(re.search(r'[a-z]', password))  # Avoir des minuscules
    has_uppercase = bool(re.search(r'[A-Z]', password))  # Avoir des majuscules
    has_digits = bool(re.search(r'\d', password))  # Avoir des chiffres
    has_special_chars = bool(re.search(r'[^a-zA-Z0-9]', password))  # Avoir des caractères spéciaux

    # Vérification des mots communs et simples
    common_words = ["password", "12345", "qwerty", "admin", "letmein", "welcome", "abc123"]
    contains_common_word = any(word in password.lower() for word in common_words)

    # Calcul du score global
    score = 0

    # Longueur : plus de 8 caractères augmente la sécurité
    if length_score:
        score += 1

    # Complexité : au moins 3 des critères de complexité (majuscules, minuscules, chiffres, caractères spéciaux)
    complexity_criteria = sum([has_lowercase, has_uppercase, has_digits, has_special_chars])
    if complexity_criteria >= 3:
        score += 2
    elif complexity_criteria == 2:
        score += 1

    # Si le mot de passe contient des mots communs, réduire le score
    if contains_common_word:
        score -= 1

    # Attribution de la criticité  0 = très faible, 1 = faible, 2 = moyen, 3 = fort, 4 = très fort
    return max(0, min(score, 4))  # Limiter le score entre 0 et 4