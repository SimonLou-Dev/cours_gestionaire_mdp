import { useState } from 'react'
import {NavLink, Route, Routes} from "react-router";
import Home from "./Home.js";
import Passwords from "./Passwords.jsx";
import Login from "./auth/Login.jsx";
import Register from "./auth/Register.jsx";


function App() {
  const [count, setCount] = useState(0)

  return (
    <div className={"w-screen h-screen"}>
      <header className={"flex flex-raw justify-between bg-gray-200 h-20 p-5"}>
          <div className={"mt-auto mb-auto flex flex-raw "}>
              <NavLink to={"/"} className={"ml-5 mr-5"}>Home</NavLink>
              <NavLink to={"/passwords"} className={"ml-5 mr-5"}>passwords</NavLink>
          </div>
          <NavLink to={"/login"} className={"mt-auto mb-auto"}>Login</NavLink>
      </header>
        <Routes className={"w-full h-[calc(100%-var(--spacing) * 5)] bg-orange-200"}>
            <Route path={"/"} element={<Home />} />
            <Route path={"/passwords"} element={<Passwords />} />
            <Route path={"/login"} element={<Login />} />
            <Route path={"/register"} element={<Register />} />
        </Routes>
    </div>
  )
}

export default App
