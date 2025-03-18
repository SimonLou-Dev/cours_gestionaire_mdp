import {useState} from "react";
import {NavLink} from "react-router";

export default function Login() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState([]);

    const handleSubmit = async (e) => {
    }

  return (
      <div className="flex items-center justify-center min-h-screen bg-gray-100">
          <div className="bg-white p-8 rounded-lg shadow-lg w-96">
              <h2 className="text-2xl font-bold text-center text-gray-700 mb-6">Connexion</h2>
              {error && <div className="mb-4 text-red-500 text-sm">{error}</div>}
                  <div>
                      <label className="block text-gray-700">Email</label>
                      <input
                          type="email"
                          className="w-full p-2 border border-gray-300 rounded mt-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                      />
                  </div>
                  <div>
                      <label className="block text-gray-700">Mot de passe</label>
                      <input
                          type="password"
                          className="w-full p-2 border border-gray-300 rounded mt-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                      />
                  </div>
                  <button
                      className="w-full mt-5 bg-blue-500 text-white p-2 rounded hover:bg-blue-600 transition duration-200"
                      onClick={handleSubmit}
                  >
                      Se connecter
                  </button>
                  <NavLink to={"/register"} className="text-blue-500 text-center block mt-4">Pas de compte ? S'inscrire</NavLink>
          </div>
      </div>
  );
}