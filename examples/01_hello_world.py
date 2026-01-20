"""
UAIP Hello World
The simplest possible example - create an agent and verify its identity.
"""

from uaip.sdk import UAIP_Enterprise_SDK


def main():
    print("🚀 UAIP Hello World Example\n")
    
    # Create an agent
    print("Creating agent...")
    agent = UAIPAgent(
        name="HelloWorldBot",
        company="ExampleCorp"
    )
    
    # Print agent details
    print(f"\n✅ Agent created successfully!\n")
    print(f"Name: {agent.name}")
    print(f"Company: {agent.company}")
    print(f"DID: {agent.did}")
    print(f"Public Key: {agent.public_key[:32]}...")
    
    # Verify the agent can sign messages
    message = "Hello, UAIP!"
    signature = agent.sign(message)
    
    print(f"\n🔐 Cryptographic Signing Test:")
    print(f"Message: '{message}'")
    print(f"Signature: {signature[:32]}...")
    
    # Verify the signature
    is_valid = agent.verify_identity()
    print(f"Identity Valid: {is_valid}")
    
    print("\n✅ All systems operational!")


if __name__ == "__main__":
    main()
