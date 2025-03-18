import {useRef, useState} from "react";

export default function Passwords() {
const [entries, setEntries] = useState([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [copyProgress, setCopyProgress] = useState(0);
  const [currentEntry, setCurrentEntry] = useState(null);
  let progressInterval;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopyProgress(100);

    progressInterval = setInterval(() => {
      setCopyProgress((prev) => {
        if (prev <= 0) {
          clearInterval(progressInterval);
          navigator.clipboard.writeText("");
          return 0;
        }
        return prev - 6.67;
      });
    }, 1000);
  };

  const addEntry = (entry) => {
    setEntries([...entries, entry]);
    setShowAddModal(false);
  };

  const updateEntry = (updatedEntry) => {
    setEntries(entries.map((entry) => (entry.email === updatedEntry.email ? updatedEntry : entry)));
    setShowEditModal(false);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 p-6">
      <div className="w-full max-w-5xl bg-white p-6 rounded-lg shadow-lg overflow-x-auto sticky top-0">
        <div className="flex justify-between items-center mb-4">
          <button
            className="bg-blue-500 text-white p-3 rounded"
            onClick={() => setShowAddModal(true)}
          >
            Ajouter un identifiant
          </button>
          <div className="w-1/3 bg-gray-300 rounded-full h-2.5 overflow-hidden">
            <div className="bg-blue-500 h-2.5 transition-all" style={{ width: `${copyProgress}%` }}></div>
          </div>
        </div>
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-gray-200">
              <th className="border p-3">Pseudo</th>
              <th className="border p-3">Email</th>
              <th className="border p-3">Mot de passe</th>
              <th className="border p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => (
              <tr key={index} className="border">
                <td className="border p-3">{entry.pseudo}</td>
                <td className="border p-3">{entry.email}</td>
                <td className="border p-3">********</td>
                <td className="border p-3 space-x-2">
                  <button className="text-blue-500" onClick={() => handleCopy(entry.password)}>Copier</button>
                  <button className="text-green-500" onClick={() => { setCurrentEntry(entry); setShowEditModal(true); }}>Modifier</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showAddModal && <Modal title="Ajouter un identifiant" onClose={() => setShowAddModal(false)} onSave={addEntry} />}
      {showEditModal && <Modal title="Modifier un identifiant" onClose={() => setShowEditModal(false)} onSave={updateEntry} entry={currentEntry} />}
    </div>
  );
}

function Modal({ title, onClose, onSave, entry = {} }) {
  const [pseudo, setPseudo] = useState(entry.pseudo || "");
  const [email, setEmail] = useState(entry.email || "");
  const [password, setPassword] = useState(entry.password || "");

  const handleSubmit = () => {
    if (!pseudo || !email || !password) return;
    onSave({ pseudo, email, password });
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white p-6 rounded shadow-lg w-96">
        <h2 className="text-lg font-bold mb-4">{title}</h2>
        <input className="w-full mb-2 p-2 border" placeholder="Pseudo" value={pseudo} onChange={(e) => setPseudo(e.target.value)} />
        <input className="w-full mb-2 p-2 border" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={title === "Modifier un identifiant"} />
        <input className="w-full mb-2 p-2 border" placeholder="Mot de passe" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button className="bg-blue-500 text-white p-2 w-full mb-2" onClick={handleSubmit}>Enregistrer</button>
        <button className="bg-gray-500 text-white p-2 w-full" onClick={onClose}>Annuler</button>
      </div>
    </div>
  );
}