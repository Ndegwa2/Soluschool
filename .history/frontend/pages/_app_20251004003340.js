import '../styles/globals.css'
import { AuthProvider } from '../lib/AuthContext'
import Header from '../components/layout/Header'

function MyApp({ Component, pageProps }) {
  return (
    <AuthProvider>
      <Header />
      <Component {...pageProps} />
    </AuthProvider>
  )
}

export default MyApp