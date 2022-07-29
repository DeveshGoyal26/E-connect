import './App.css'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import HomePage from './Components/HomePage/HomePage'
import Login from './Components/Login/Login'
import Signup from './Components/Login/Signup'
import './App.css'
import Header from './Components/Header/Header'
import Footer from './Components/Footer.jsx/Footer'
import ErrorPage from './Components/ErrorPage/ErrorPage'
import { useEffect, useState } from 'react'
import { useContext } from 'react'
import { AuthContext } from './contextApi/AuthContext'
import Chat from './Components/Chat/Chat'
import Main from './Components/Main/Main'

function App() {
  const location = useLocation()
  const { login } = useContext(AuthContext)
  // const navigate = useNavigate()

  return (
    <div className="bg-white shadow dark:bg-gray-800">
      {location.pathname === '/login' ||
        location.pathname === '/signup' ||
        location.pathname === '/chat' || !login ? null : (
        <Header />
      )}

      <Routes>
        <Route path="/" element={login ? <HomePage /> : <Login />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/chat" element={login ? <Chat /> : <Login />} />
        <Route path="*" element={<ErrorPage />} />
      </Routes>

      {location.pathname === '/login' ||
        location.pathname === '/signup' ||
        location.pathname == '/chat' || !login ? null : (
        <Footer />
      )}
    </div>
  )
}

export default App
