import '../styles/globals.css'
import Head from 'next/head'
import { AuthProvider } from '../lib/AuthContext'
import Header from '../components/layout/Header'

function MyApp({ Component, pageProps }) {
  return (
    <>
      <Head>
        <link
          href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </Head>
      <AuthProvider>
        <Header />
        <Component {...pageProps} />
      </AuthProvider>
    </>
  )
}

export default MyApp