import { Component } from '@angular/core';
import { Flight } from '../../entities/flight';
import { FlightService } from '../services/flight.service';
import { OAuthService } from '../../../../../lib/src/oauth-service';

@Component({
  selector: 'app-flight-search',
  templateUrl: './flight-search.component.html',
  styleUrls: ['./flight-search.component.css']
})
export class FlightSearchComponent {
  public from = 'Graz';
  public to = '';
  public selectedFlight: Flight;

  constructor(
    private flightService: FlightService,
    private oauthService: OAuthService
  ) {
    console.log('access-token', this.oauthService.getAccessToken());
  }

  // cmp.flights
  public get flights() {
    return this.flightService.flights;
  }

  public select(f: Flight): void {
    this.selectedFlight = f;
  }

  public search(): void {
    this.flightService.find(this.from, this.to);

    // .map(function(resp) { return resp.json() })
  }
}
