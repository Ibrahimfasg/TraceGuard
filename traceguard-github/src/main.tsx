import { createRoot } from 'react-dom/client';

import App from './App';

import './index.css';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('The page is missing its root element.');
}

createRoot(rootElement).render(<App />);
