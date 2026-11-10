import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Overview from "./pages/Overview";
import Sessions from "./pages/Sessions";
import Nodes from "./pages/Nodes";
import About from "./pages/About";
import Learn from "./pages/Learn";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <header className="app-header">
          <div className="app-title">Aletheia</div>
          <nav className="app-nav">
            <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
              Overview
            </NavLink>
            <NavLink to="/sessions" className={({ isActive }) => (isActive ? "active" : "")}>
              Sessions
            </NavLink>
            <NavLink to="/nodes" className={({ isActive }) => (isActive ? "active" : "")}>
              Nodes
            </NavLink>
            <NavLink to="/about" className={({ isActive }) => (isActive ? "active" : "")}>
              About
            </NavLink>
            <NavLink to="/learn" className={({ isActive }) => (isActive ? "active" : "")}>
              Learn
            </NavLink>
          </nav>
        </header>
        <main className="app-main">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/nodes" element={<Nodes />} />
            <Route path="/about" element={<About />} />
            <Route path="/learn" element={<Learn />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
