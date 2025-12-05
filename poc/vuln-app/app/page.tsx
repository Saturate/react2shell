import { submitMessage } from './actions'

export default function Home() {
  return (
    <main style={{ padding: '2rem', fontFamily: 'system-ui' }}>
      <h1>CVE-2025-55182 Vulnerable App</h1>
      <p>This is a vulnerable Next.js application for educational purposes.</p>

      <form action={submitMessage}>
        <div style={{ marginTop: '2rem' }}>
          <label htmlFor="message">Message:</label>
          <br />
          <input
            type="text"
            id="message"
            name="message"
            placeholder="Enter a message"
            style={{ padding: '0.5rem', marginTop: '0.5rem', width: '300px' }}
          />
        </div>
        <button
          type="submit"
          style={{
            marginTop: '1rem',
            padding: '0.5rem 1rem',
            background: '#0070f3',
            color: 'white',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer'
          }}
        >
          Submit
        </button>
      </form>

      <div style={{ marginTop: '2rem', padding: '1rem', background: '#f5f5f5', borderRadius: '5px' }}>
        <h3>Info</h3>
        <p>Next.js: 15.0.0 (Vulnerable)</p>
        <p>React: 19.0.0 (Vulnerable)</p>
        <p>This app contains CVE-2025-55182</p>
      </div>
    </main>
  )
}
