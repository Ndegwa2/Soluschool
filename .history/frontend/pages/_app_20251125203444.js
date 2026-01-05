import React from 'react'
import Head from 'next/head'
import '../styles/globals.css'
import { Poppins } from 'next/font/google'
import { AuthProvider } from '../lib/AuthContext'
import Header from '../components/layout/Header'

const poppins = Poppins({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  display: 'swap',
})

function MyApp({ Component, pageProps }) {
  return (
    <div className={poppins.className}>
      <Head>
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <AuthProvider>
        <Header />
        <Component {...pageProps} />
      </AuthProvider>
    </div>
  )
}

export default MyApp