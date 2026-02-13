@extends('payment-views.layouts.master')

@section('content')
<div style="font-family: system-ui, -apple-system, sans-serif; max-width: 360px; margin: 2rem auto; padding: 1.5rem; text-align: center;">
    <h1 style="font-size: 1.25rem; margin-bottom: 1rem; color: #333;">Ouvrir l'application pour payer</h1>
    <p style="color: #666; margin-bottom: 1.5rem; font-size: 0.95rem;">Choisissez l'application avec laquelle vous souhaitez payer :</p>

    @if(!empty($maxit_url))
    <p style="margin-bottom: 0.5rem;">
        <a href="{{ $maxit_url }}" style="display: inline-block; padding: 0.75rem 1.5rem; background: #ff6600; color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600;">Ouvrir avec Max It</a>
    </p>
    @endif

    @if(!empty($om_url))
    <p style="margin-bottom: 0.5rem;">
        <a href="{{ $om_url }}" style="display: inline-block; padding: 0.75rem 1.5rem; background: #ff6600; color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600;">Ouvrir avec Orange Money</a>
    </p>
    @endif

    <p style="margin-top: 1.5rem; font-size: 0.85rem; color: #888;">En appuyant sur le bouton, l'application s'ouvrira pour finaliser le paiement.</p>
</div>
@endsection
