'use server'

export async function submitMessage(formData: FormData) {
  const message = formData.get('message')

  return {
    success: true,
    message: `Received: ${message}`,
    timestamp: new Date().toISOString()
  }
}
