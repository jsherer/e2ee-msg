import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LockScreen } from '../../components/LockScreen';

describe('LockScreen', () => {
  const mockProps = {
    masterKey: '',
    setMasterKey: jest.fn(),
    onUnlock: jest.fn(),
    waitingForMasterKey: false,
    onFreshStart: jest.fn()
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render the lock screen', () => {
    render(<LockScreen {...mockProps} />);
    
    expect(screen.getByText('🔐 E2EE Local Messenger')).toBeInTheDocument();
    expect(screen.getByText('Enter your master key to unlock')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Master key / password')).toBeInTheDocument();
    expect(screen.getByText('Unlock')).toBeInTheDocument();
  });

  it('should update master key on input', async () => {
    const user = userEvent.setup();
    const setMasterKey = jest.fn();
    render(<LockScreen {...mockProps} setMasterKey={setMasterKey} />);
    
    const input = screen.getByPlaceholderText('Master key / password');
    await user.type(input, 'test-key');
    
    // UserEvent calls onChange for each character typed
    expect(setMasterKey).toHaveBeenCalled();
  });

  it('should disable unlock button when key is too short', () => {
    render(<LockScreen {...mockProps} masterKey="short" />);
    
    const unlockButton = screen.getByText('Unlock');
    expect(unlockButton).toBeDisabled();
  });

  it('should enable unlock button when key is long enough', () => {
    render(<LockScreen {...mockProps} masterKey="this-is-long-enough" />);
    
    const unlockButton = screen.getByText('Unlock');
    expect(unlockButton).not.toBeDisabled();
  });

  it('should call onUnlock when unlock button is clicked', () => {
    render(<LockScreen {...mockProps} masterKey="valid-master-key-12345" />);
    
    const unlockButton = screen.getByText('Unlock');
    fireEvent.click(unlockButton);
    
    expect(mockProps.onUnlock).toHaveBeenCalledTimes(1);
  });

  it('should call onUnlock when Enter key is pressed', () => {
    render(<LockScreen {...mockProps} masterKey="valid-master-key-12345" />);
    
    const input = screen.getByPlaceholderText('Master key / password');
    fireEvent.keyPress(input, { key: 'Enter', code: 'Enter', charCode: 13 });
    
    expect(mockProps.onUnlock).toHaveBeenCalledTimes(1);
  });


  it('should show waiting message when waitingForMasterKey is true', () => {
    render(<LockScreen {...mockProps} waitingForMasterKey={true} />);
    
    expect(screen.getByText('📋 Encrypted key found in URL. Enter your master key to restore.')).toBeInTheDocument();
    expect(screen.getByText('(Need a fresh start?)')).toBeInTheDocument();
  });

  it('should show character count when key is too short', () => {
    render(<LockScreen {...mockProps} masterKey="hello" />);
    
    expect(screen.getByText('5/12 characters minimum')).toBeInTheDocument();
  });

  it('should call onFreshStart when fresh start is clicked and confirmed', () => {
    window.confirm = jest.fn(() => true);
    render(<LockScreen {...mockProps} waitingForMasterKey={true} />);
    
    const freshStartButton = screen.getByText('(Need a fresh start?)');
    fireEvent.click(freshStartButton);
    
    expect(window.confirm).toHaveBeenCalledWith(
      expect.stringContaining('This will clear the encrypted private key')
    );
    expect(mockProps.onFreshStart).toHaveBeenCalledTimes(1);
  });

  it('should not call onFreshStart when fresh start is cancelled', () => {
    window.confirm = jest.fn(() => false);
    render(<LockScreen {...mockProps} waitingForMasterKey={true} />);
    
    const freshStartButton = screen.getByText('(Need a fresh start?)');
    fireEvent.click(freshStartButton);
    
    expect(window.confirm).toHaveBeenCalled();
    expect(mockProps.onFreshStart).not.toHaveBeenCalled();
  });
});