const stripe = Stripe('pk_test_51NWbl0AnVKG20ORq3ML4Gw1AsRYCKw3P9jwdfdrw47mzRhisAYC24f4nYNnBPitQdTO8buAgd68vLLlTgrp8gGHN002apdwN2j');
const form = document.getElementById('payment-form');

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const {error} = await stripe.confirmPayment({
    //`Elements` instance that was used to create the Payment Element
    confirmParams: {
      return_url: 'http://localhost:3306/success',
    },
  });

  if (error) {
    // This point will only be reached if there is an immediate error when
    // confirming the payment. Show error to your customer (for example, payment
    // details incomplete)
    const messageContainer = document.querySelector('#error-message');
    messageContainer.textContent = error.message;
  } else {
    // Your customer will be redirected to your `return_url`. For some payment
    // methods like iDEAL, your customer will be redirected to an intermediate
    // site first to authorize the payment, then redirected to the `return_url`.
  }
});