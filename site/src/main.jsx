import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './App.css'
import {BrowserRouter} from "react-router";
import App from "./views/App.jsx";

createRoot(document.getElementById('root')).render(
  <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
  </StrictMode>,
)
