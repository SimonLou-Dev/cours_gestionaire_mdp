"""Classe avec les DTO pour les MDP."""

from pydantic import BaseModel


class PasswordOut(BaseModel):
    """DTO utilisé lors de la récupération d'un mot de passe.

    Attributs :
        id (int) : Identifiant unique de l'entrée de mot de passe.
        title (str) : Titre de l'entrée de mot de passe.
        username (str) : Nom d'utilisateur associé à l'entrée.
        url (str) : URL du service associé.
        email (str) : Adresse e-mail liée à l'entrée.
        password (str) : Mot de passe déchiffré.
        complexity (int) : Indicateur de la complexité du mot de passe.

    """

    id: int
    title: str
    username: str
    url: str
    email: str
    password: str
    complexity: int

    class Config:
        """Permet de convertir les attributs de la classe en dictionnaire.

        Attributs :

            orm_mode (bool) : Indique que le modèle doit être compatible avec les objets ORM.
        """

        from_attributes = True
