import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

describe('smoke', () => {
  it('renders a simple component', () => {
    render(<div>hello</div>)
    expect(screen.getByText('hello')).toBeInTheDocument()
  })

  it('does math', () => {
    expect(1 + 1).toBe(2)
  })
})
